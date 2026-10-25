//! Connection handling and request dispatch.
//!
//! Abuse limits (see `Limits` in `config.rs` and SECURITY_REVIEW.md, H-1):
//! connections are admitted per IP before the TLS handshake and per device
//! after `Hello`; sending is bounded per sender per hour and per recipient
//! queue; invite mailboxes are capped and bound to their participants;
//! failed registrations are throttled per IP (M-5).
//!
//! All database work runs on blocking threads through `DbPool` (L-2).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use yo_proto::frame::FramedConn;
use yo_proto::msg::{
    DeleteInbox, Envelope, ErrorCode, Event, OutEnvelope, Request, Response, ServerFrame, SignedDeviceList,
    SignedPreKey,
};
use yo_proto::{DeviceId, InboxId, PROTOCOL_VERSION, now, tls};

use crate::config::{Config, Limits, Registration};
use crate::db::InboxState;
use crate::mailbox::{MailboxError, Mailboxes};
use crate::pool::DbPool;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const LONG_POLL: Duration = Duration::from_secs(25);
const MAX_PREKEYS: usize = 100;
const MAX_ENVELOPES_PER_SEND: usize = 64;
/// Largest padded payload (256 KiB) plus Olm and encoding overhead.
pub const MAX_BLOB: usize = 272 * 1024;
const FETCH_LIMIT: usize = 200;
/// A `Fetch` response must fit inside `yo_proto::MAX_FRAME` with room to spare.
pub const FETCH_MAX_BYTES: usize = 1024 * 1024;
const MIB: u64 = 1024 * 1024;

type Subscribers = HashMap<DeviceId, Vec<mpsc::UnboundedSender<Envelope>>>;
type Windows<K> = HashMap<(K, &'static str), (Instant, u32)>;

struct IpState {
    active: u32,
    tokens: f64,
    refilled: Instant,
}

/// Cumulative abuse counters, logged once a minute for operators to scrape
/// (SECURITY_REVIEW.md 3.6). They hold no per-user information.
#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    refused_ip: AtomicU64,
    refused_device_conn: AtomicU64,
    refused_registration: AtomicU64,
    rate_limited: AtomicU64,
}

pub struct Server {
    db: DbPool,
    mailboxes: Mutex<Mailboxes>,
    subs: Mutex<Subscribers>,
    /// Fixed-window per-device request counters.
    windows: Mutex<Windows<DeviceId>>,
    /// Fixed-window per-IP counters (failed registrations).
    ip_windows: Mutex<Windows<IpAddr>>,
    ips: Mutex<HashMap<IpAddr, IpState>>,
    device_conns: Mutex<HashMap<DeviceId, u32>>,
    /// Bytes sent per device in the current hour.
    send_bytes: Mutex<HashMap<DeviceId, (Instant, u64)>>,
    metrics: Metrics,
    limits: Limits,
    registration: Registration,
    ttl_days: u64,
    max_devices: usize,
}

/// Holds one slot of an IP's connection budget; released on drop.
struct IpGuard {
    server: Arc<Server>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        if let Some(s) = self.server.ips.lock().expect("ip lock").get_mut(&self.ip) {
            s.active = s.active.saturating_sub(1);
        }
    }
}

/// Holds one slot of a device's connection budget; released on drop.
struct DeviceGuard {
    server: Arc<Server>,
    device: DeviceId,
}

impl Drop for DeviceGuard {
    fn drop(&mut self) {
        if let Some(n) = self.server.device_conns.lock().expect("device lock").get_mut(&self.device) {
            *n = n.saturating_sub(1);
        }
    }
}

fn err(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error { code, message: message.into() }
}

fn internal(e: impl std::fmt::Display) -> Response {
    warn!("internal error: {e}");
    err(ErrorCode::Internal, "internal server error")
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    }
}

/// Count one event in a per-key fixed one-minute window; true while the
/// count (including this event) is at most `max`.
fn window_allow<K: std::hash::Hash + Eq>(w: &mut Windows<K>, key: K, action: &'static str, max: u32) -> bool {
    let e = w.entry((key, action)).or_insert((Instant::now(), 0));
    if e.0.elapsed() > Duration::from_secs(60) {
        *e = (Instant::now(), 0);
    }
    e.1 += 1;
    e.1 <= max
}

impl Server {
    pub fn new(db: DbPool, cfg: &Config) -> Arc<Server> {
        Arc::new(Server {
            db,
            mailboxes: Mutex::new(Mailboxes::new(cfg.limits.mailboxes)),
            subs: Mutex::new(HashMap::new()),
            windows: Mutex::new(HashMap::new()),
            ip_windows: Mutex::new(HashMap::new()),
            ips: Mutex::new(HashMap::new()),
            device_conns: Mutex::new(HashMap::new()),
            send_bytes: Mutex::new(HashMap::new()),
            metrics: Metrics::default(),
            limits: cfg.limits.clone(),
            registration: cfg.registration,
            ttl_days: cfg.message_ttl_days,
            max_devices: cfg.max_devices,
        })
    }

    /// Accept connections forever.
    pub async fn serve(self: Arc<Self>, listener: TcpListener, tls: Arc<rustls::ServerConfig>) -> std::io::Result<()> {
        let acceptor = TlsAcceptor::from(tls);
        let housekeeping = self.clone();
        tokio::spawn(async move {
            loop {
                housekeeping.housekeeping().await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        loop {
            let (tcp, addr) = listener.accept().await?;
            let ip = canonical(addr.ip());
            // Admission per IP happens before any TLS work is done.
            let Some(ip_guard) = self.admit_ip(ip) else {
                self.metrics.refused_ip.fetch_add(1, Ordering::Relaxed);
                debug!("refused connection from {ip}: per-IP limit");
                continue;
            };
            self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
            let me = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ip_guard = ip_guard;
                if let Err(e) = me.connection(tcp, acceptor, ip).await {
                    debug!("{addr}: {e}");
                }
            });
        }
    }

    async fn housekeeping(&self) {
        let n = now();
        let (env_before, burn_before) = (n.saturating_sub(self.ttl_days * 86400), n.saturating_sub(30 * 86400));
        let removed = self.db.run(move |db| db.expire(env_before, burn_before)).await;
        if let Ok(r) = removed
            && r > 0
        {
            info!("expired {r} old records");
        }
        let live_mailboxes = {
            let mut mb = self.mailboxes.lock().expect("mailbox lock");
            mb.expire();
            mb.len()
        };
        let m = &self.metrics;
        info!(
            "metrics accepted={} refused_ip={} refused_device_conn={} refused_registration={} rate_limited={} live_mailboxes={}",
            m.accepted.load(Ordering::Relaxed),
            m.refused_ip.load(Ordering::Relaxed),
            m.refused_device_conn.load(Ordering::Relaxed),
            m.refused_registration.load(Ordering::Relaxed),
            m.rate_limited.load(Ordering::Relaxed),
            live_mailboxes,
        );
        self.windows.lock().expect("windows lock").retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
        self.ip_windows.lock().expect("ip windows lock").retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
        let full = self.limits.new_connections_per_minute_per_ip as f64;
        self.ips.lock().expect("ip lock").retain(|_, s| s.active > 0 || s.tokens < full);
        self.device_conns.lock().expect("device lock").retain(|_, n| *n > 0);
        self.send_bytes.lock().expect("send lock").retain(|_, (t, _)| t.elapsed() < Duration::from_secs(3600));
        self.subs.lock().expect("subs lock").retain(|_, v| {
            v.retain(|tx| !tx.is_closed());
            !v.is_empty()
        });
    }

    /// Simple fixed-window rate limit per device and action.
    fn allow(&self, device: &DeviceId, action: &'static str, per_minute: u32) -> bool {
        window_allow(&mut self.windows.lock().expect("windows lock"), *device, action, per_minute)
    }

    /// Token bucket (new connections per minute) plus a concurrency cap, per IP.
    fn admit_ip(self: &Arc<Self>, ip: IpAddr) -> Option<IpGuard> {
        let per_min = self.limits.new_connections_per_minute_per_ip.max(1) as f64;
        let mut ips = self.ips.lock().expect("ip lock");
        let st = ips.entry(ip).or_insert(IpState { active: 0, tokens: per_min, refilled: Instant::now() });
        let elapsed = st.refilled.elapsed().as_secs_f64();
        st.tokens = (st.tokens + elapsed * per_min / 60.0).min(per_min);
        st.refilled = Instant::now();
        if st.active >= self.limits.connections_per_ip || st.tokens < 1.0 {
            return None;
        }
        st.tokens -= 1.0;
        st.active += 1;
        Some(IpGuard { server: self.clone(), ip })
    }

    fn admit_device(self: &Arc<Self>, device: DeviceId) -> Option<DeviceGuard> {
        let mut d = self.device_conns.lock().expect("device lock");
        let n = d.entry(device).or_insert(0);
        if *n >= self.limits.connections_per_device {
            return None;
        }
        *n += 1;
        Some(DeviceGuard { server: self.clone(), device })
    }

    /// Charge `bytes` against the device's hourly sending budget.
    fn charge_send(&self, device: &DeviceId, bytes: u64) -> bool {
        let mut s = self.send_bytes.lock().expect("send lock");
        let e = s.entry(*device).or_insert((Instant::now(), 0));
        if e.0.elapsed() > Duration::from_secs(3600) {
            *e = (Instant::now(), 0);
        }
        if e.1 + bytes > self.limits.send_mib_per_hour_per_device * MIB {
            return false;
        }
        e.1 += bytes;
        true
    }

    async fn connection(self: Arc<Self>, tcp: TcpStream, acceptor: TlsAcceptor, ip: IpAddr) -> anyhow::Result<()> {
        tcp.set_nodelay(true)?;
        let stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await??;
        let cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or_else(|| anyhow::anyhow!("no client certificate"))?;
        let spki = tls::spki_hash(cert)?;
        let device = DeviceId::from_spki_hash(&spki);
        let mut conn = FramedConn::new(stream);

        // Every connection starts with Hello (and registration if needed).
        let hello: Request = timeout(HANDSHAKE_TIMEOUT, conn.recv()).await??;
        let mut resp = match hello {
            Request::Hello { version, token } => self.hello(&device, ip, version, token).await,
            _ => err(ErrorCode::BadRequest, "expected Hello"),
        };
        let mut _device_guard = None;
        if matches!(resp, Response::Hello { .. }) {
            match self.admit_device(device) {
                Some(g) => _device_guard = Some(g),
                None => {
                    self.metrics.refused_device_conn.fetch_add(1, Ordering::Relaxed);
                    resp = err(ErrorCode::RateLimited, "too many open connections from this device");
                }
            }
        }
        let ok = matches!(resp, Response::Hello { .. });
        conn.send(&ServerFrame::Response(resp)).await?;
        if !ok {
            return Ok(());
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<Envelope>();
        let mut subscribed = false;
        loop {
            let idle = if subscribed { Duration::from_secs(3600) } else { IDLE_TIMEOUT };
            tokio::select! {
                r = timeout(idle, conn.recv::<Request>()) => {
                    let req = match r {
                        Ok(Ok(req)) => req,
                        _ => break,
                    };
                    if matches!(req, Request::Subscribe) && !subscribed {
                        subscribed = true;
                        self.subs.lock().expect("subs lock").entry(device).or_default().push(tx.clone());
                    }
                    let resp = self.request(&device, req).await;
                    conn.send(&ServerFrame::Response(resp)).await?;
                }
                Some(env) = rx.recv() => {
                    conn.send(&ServerFrame::Event(Event::Envelope(env))).await?;
                }
            }
        }
        Ok(())
    }

    async fn hello(&self, device: &DeviceId, ip: IpAddr, version: u16, token: Option<String>) -> Response {
        if version != PROTOCOL_VERSION {
            return err(
                ErrorCode::VersionMismatch,
                format!("server speaks protocol {PROTOCOL_VERSION}, client speaks {version}"),
            );
        }
        let dev = *device;
        match self.db.run(move |db| db.is_registered(&dev)).await {
            Ok(true) => return Response::Hello { version: PROTOCOL_VERSION, device: *device },
            Ok(false) => {}
            Err(e) => return internal(e),
        }

        // Unregistered: throttle failed attempts per source address.
        let max_fail = self.limits.failed_registrations_per_minute_per_ip;
        {
            let w = self.ip_windows.lock().expect("ip windows lock");
            if let Some((t, n)) = w.get(&(ip, "register-fail"))
                && t.elapsed() < Duration::from_secs(60)
                && *n >= max_fail
            {
                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                return err(ErrorCode::RateLimited, "too many registration attempts from your address; wait a minute");
            }
        }
        let t = now();
        let registered = match self.registration {
            Registration::Open => self.db.run(move |db| db.register(&dev, t).map(|_| true)).await,
            Registration::Token => match token {
                Some(tok) => {
                    let tok = tok.trim().to_string();
                    self.db.run(move |db| db.register_with_token(&dev, &tok, t)).await
                }
                None => Ok(false),
            },
        };
        match registered {
            Ok(true) => {
                info!("registered new device {} from {ip}", device.short());
                Response::Hello { version: PROTOCOL_VERSION, device: *device }
            }
            Ok(false) => {
                window_allow(&mut self.ip_windows.lock().expect("ip windows lock"), ip, "register-fail", u32::MAX);
                self.metrics.refused_registration.fetch_add(1, Ordering::Relaxed);
                // Stable wording: fail2ban filters match on it (docs/src/server/setup.md).
                warn!("registration refused device={} ip={ip}", device.short());
                err(
                    ErrorCode::RegistrationRequired,
                    "this server needs a registration token (ask the operator for `yo-server token create`)",
                )
            }
            Err(e) => internal(e),
        }
    }

    async fn request(&self, me: &DeviceId, req: Request) -> Response {
        let me = *me;
        match req {
            Request::Hello { .. } => err(ErrorCode::BadRequest, "already said hello"),
            Request::Ping | Request::Subscribe => Response::Ok,
            Request::PutDeviceList(list) => self.put_list(me, list).await,
            Request::GetDeviceList { inbox } => match self.db.run(move |db| db.inbox(&inbox)).await {
                Ok(InboxState::Live { list, .. }) => Response::DeviceList(Some(list)),
                Ok(InboxState::Missing) => Response::DeviceList(None),
                Ok(InboxState::Burned) => err(ErrorCode::Burned, "this conversation was burned"),
                Err(e) => internal(e),
            },
            Request::PublishKeys { inbox, one_time, fallback } => self.publish(me, inbox, one_time, fallback).await,
            Request::KeyCount { inbox } => match self.db.run(move |db| db.key_count(&inbox, &me)).await {
                Ok(n) => Response::KeyCount(n),
                Err(e) => internal(e),
            },
            Request::ClaimKey { inbox, device } => {
                if !self.allow(&me, "claim", 120) {
                    return err(ErrorCode::RateLimited, "too many key claims");
                }
                match self.db.run(move |db| db.claim_key(&inbox, &device)).await {
                    Ok(k) => Response::Key(k),
                    Err(e) => internal(e),
                }
            }
            Request::Send { inbox, envelopes } => self.send(me, inbox, envelopes).await,
            Request::Fetch => match self.db.run(move |db| db.fetch(&me, FETCH_LIMIT, FETCH_MAX_BYTES)).await {
                Ok(v) => Response::Envelopes(v),
                Err(e) => internal(e),
            },
            Request::Ack { ids } => match self.db.run(move |db| db.ack(&me, &ids)).await {
                Ok(()) => Response::Ok,
                Err(e) => internal(e),
            },
            Request::DeleteInbox(d) => self.delete_inbox(d).await,
            Request::BindRevocation(b) => {
                let authority = b.authority;
                let sig = b.sig;
                if yo_crypto::rik::verify(
                    &authority,
                    &yo_proto::msg::BindRevocation::signing_bytes(&me, &authority),
                    &sig,
                )
                .is_err()
                {
                    return err(ErrorCode::Unauthorized, "bad signature");
                }
                // A device binds only its *own* authority (caller == device).
                match self.db.run(move |db| db.bind_revocation(&me, &authority)).await {
                    Ok(()) => Response::Ok,
                    Err(e) => internal(e),
                }
            }
            Request::Deregister(d) => self.deregister(d).await,
            Request::MailboxOpen => {
                if !self.allow(&me, "mailbox", 20) {
                    return err(ErrorCode::RateLimited, "too many invites, wait a minute");
                }
                match self.mailboxes.lock().expect("mailbox lock").open(me) {
                    Ok(n) => Response::Nameplate(n),
                    Err(_) => err(ErrorCode::RateLimited, "the server is busy with invites; try again in a minute"),
                }
            }
            Request::MailboxJoin { nameplate } => {
                if !self.allow(&me, "mailbox", 20) {
                    return err(ErrorCode::RateLimited, "too many invites, wait a minute");
                }
                match self.mailboxes.lock().expect("mailbox lock").join(nameplate, me) {
                    Ok(()) => Response::Ok,
                    Err(MailboxError::AlreadyJoined) => {
                        err(ErrorCode::Conflict, "that code was already used; ask for a new one")
                    }
                    Err(MailboxError::Unauthorized) => err(ErrorCode::BadRequest, "you can't join your own invite"),
                    Err(_) => err(ErrorCode::NotFound, "no such invite (expired or already used)"),
                }
            }
            Request::MailboxPut { nameplate, side, msg } => {
                if !self.allow(&me, "mailbox-io", 240) {
                    return err(ErrorCode::RateLimited, "slow down");
                }
                match self.mailboxes.lock().expect("mailbox lock").put(nameplate, me, side, msg) {
                    Ok(()) => Response::Ok,
                    Err(MailboxError::TooLarge) => err(ErrorCode::BadRequest, "mailbox message too large"),
                    Err(MailboxError::Unauthorized) => err(ErrorCode::Unauthorized, "not a participant of this invite"),
                    Err(_) => err(ErrorCode::NotFound, "invite closed"),
                }
            }
            Request::MailboxGet { nameplate, side, index } => {
                if !self.allow(&me, "mailbox-io", 240) {
                    return err(ErrorCode::RateLimited, "slow down");
                }
                let deadline = tokio::time::Instant::now() + LONG_POLL;
                loop {
                    let got = self.mailboxes.lock().expect("mailbox lock").get(nameplate, me, side, index);
                    let (msg, notify) = match got {
                        Ok(v) => v,
                        Err(MailboxError::Unauthorized) => {
                            return err(ErrorCode::Unauthorized, "not a participant of this invite");
                        }
                        Err(_) => return err(ErrorCode::NotFound, "invite closed"),
                    };
                    if msg.is_some() {
                        return Response::MailboxMsg(msg);
                    }
                    let notified = notify.notified();
                    // Re-check after registering interest to avoid a lost wakeup.
                    if let Ok((Some(m), _)) =
                        self.mailboxes.lock().expect("mailbox lock").get(nameplate, me, side, index)
                    {
                        return Response::MailboxMsg(Some(m));
                    }
                    if tokio::time::timeout_at(deadline, notified).await.is_err() {
                        return Response::MailboxMsg(None);
                    }
                }
            }
            Request::MailboxClose { nameplate } => {
                match self.mailboxes.lock().expect("mailbox lock").close(nameplate, me) {
                    Ok(()) | Err(MailboxError::NotFound) => Response::Ok,
                    Err(_) => err(ErrorCode::Unauthorized, "not a participant of this invite"),
                }
            }
        }
    }

    async fn put_list(&self, me: DeviceId, signed: SignedDeviceList) -> Response {
        if let Err(e) = yo_crypto::devices::verify_list(&signed, None) {
            return err(ErrorCode::Unauthorized, e.to_string());
        }
        if signed.list.devices.len() > self.max_devices {
            return err(ErrorCode::BadRequest, format!("at most {} devices per inbox", self.max_devices));
        }
        let in_new = signed.list.devices.iter().any(|d| d.device == me);
        self.db
            .run(move |db| {
                // Every listed device must be a registered device of this
                // server, so nobody can queue envelopes for a stranger (L-1).
                for d in &signed.list.devices {
                    match db.is_registered(&d.device) {
                        Ok(true) => {}
                        Ok(false) => {
                            return err(
                                ErrorCode::BadRequest,
                                format!("device {} is not registered here", d.device.short()),
                            );
                        }
                        Err(e) => return internal(e),
                    }
                }
                match db.inbox(&signed.list.inbox) {
                    Err(e) => return internal(e),
                    Ok(InboxState::Burned) => return err(ErrorCode::Burned, "this conversation was burned"),
                    Ok(InboxState::Missing) => {
                        if !in_new {
                            return err(ErrorCode::Unauthorized, "a new inbox must include the creating device");
                        }
                    }
                    Ok(InboxState::Live { version, list }) => {
                        if signed.list.version <= version {
                            return err(ErrorCode::Conflict, "device list changed; refetch and retry");
                        }
                        let in_old = list.list.devices.iter().any(|d| d.device == me);
                        if !in_new && !in_old {
                            return err(ErrorCode::Unauthorized, "not a member of this inbox");
                        }
                    }
                }
                match db.put_list(&signed) {
                    Ok(()) => Response::Ok,
                    Err(e) => internal(e),
                }
            })
            .await
    }

    async fn publish(
        &self,
        me: DeviceId,
        inbox: InboxId,
        one_time: Vec<SignedPreKey>,
        fallback: Option<SignedPreKey>,
    ) -> Response {
        if one_time.len() > MAX_PREKEYS {
            return err(ErrorCode::BadRequest, "too many keys");
        }
        self.db
            .run(move |db| {
                match db.is_member(&inbox, &me) {
                    Ok(true) => {}
                    Ok(false) => return err(ErrorCode::Unauthorized, "not a member of this inbox"),
                    Err(e) => return internal(e),
                }
                match db.publish_keys(&inbox, &me, &one_time, fallback.as_ref(), MAX_PREKEYS) {
                    Ok(()) => Response::Ok,
                    Err(e) => internal(e),
                }
            })
            .await
    }

    async fn send(&self, me: DeviceId, inbox: InboxId, envelopes: Vec<OutEnvelope>) -> Response {
        if envelopes.len() > MAX_ENVELOPES_PER_SEND || envelopes.iter().any(|e| e.blob.len() > MAX_BLOB) {
            return err(ErrorCode::BadRequest, "message too large");
        }
        if !self.allow(&me, "send", self.limits.sends_per_minute) {
            return err(ErrorCode::RateLimited, "slow down");
        }
        let total: u64 = envelopes.iter().map(|e| e.blob.len() as u64).sum();
        if !self.charge_send(&me, total) {
            return err(ErrorCode::RateLimited, "hourly sending limit reached; try again later");
        }
        let quota = self.limits.queue_mib_per_device * MIB;
        let stored: Result<Vec<(DeviceId, Envelope)>, Response> = self
            .db
            .run(move |db| {
                let list = match db.inbox(&inbox) {
                    Ok(InboxState::Live { list, .. }) => list,
                    Ok(InboxState::Burned) => return Err(err(ErrorCode::Burned, "this conversation was burned")),
                    Ok(InboxState::Missing) => return Err(err(ErrorCode::NotFound, "no such inbox")),
                    Err(e) => return Err(internal(e)),
                };
                if envelopes.iter().any(|e| !list.list.devices.iter().any(|d| d.device == e.device)) {
                    return Err(err(ErrorCode::Conflict, "device list changed; refetch and retry"));
                }
                // Per-recipient queue quota, checked for the whole batch before
                // any envelope is stored so a send is all-or-nothing.
                let mut incoming: HashMap<DeviceId, u64> = HashMap::new();
                for e in &envelopes {
                    *incoming.entry(e.device).or_default() += e.blob.len() as u64;
                }
                for (device, add) in &incoming {
                    match db.queued_bytes(device) {
                        Ok(q) if q + add > quota => {
                            return Err(err(
                                ErrorCode::RateLimited,
                                "a recipient's message queue is full; try again later",
                            ));
                        }
                        Ok(_) => {}
                        Err(e) => return Err(internal(e)),
                    }
                }
                let from_member = list.list.devices.iter().any(|d| d.device == me);
                let ts = now();
                let mut stored = Vec::with_capacity(envelopes.len());
                for e in envelopes {
                    match db.insert_envelope(&e.device, &inbox, &me, from_member, ts, &e.blob) {
                        Ok(env) => stored.push((e.device, env)),
                        Err(e) => return Err(internal(e)),
                    }
                }
                Ok(stored)
            })
            .await;
        let stored = match stored {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        let subs = self.subs.lock().expect("subs lock");
        for (device, env) in stored {
            if let Some(txs) = subs.get(&device) {
                for tx in txs {
                    let _ = tx.send(env.clone());
                }
            }
        }
        Response::Ok
    }

    async fn deregister(&self, d: yo_proto::msg::Deregister) -> Response {
        if now().abs_diff(d.ts) > 86400 {
            return err(ErrorCode::BadRequest, "request expired; check your clock");
        }
        if yo_crypto::rik::verify(&d.authority, &yo_proto::msg::Deregister::signing_bytes(&d.device, d.ts), &d.sig)
            .is_err()
        {
            return err(ErrorCode::Unauthorized, "bad signature");
        }
        let device = d.device;
        let authority = d.authority;
        let bound = match self.db.run(move |db| db.revocation_of(&device)).await {
            Ok(b) => b,
            Err(e) => return internal(e),
        };
        match bound {
            Some(a) if a == authority => {}
            // No bound authority, or a different one: refuse. Never reveal which.
            _ => return err(ErrorCode::Unauthorized, "not authorized to deregister that device"),
        }
        match self.db.run(move |db| db.deregister(&device)).await {
            Ok(()) => {
                info!("deregistered device {}", device.short());
                Response::Ok
            }
            Err(e) => internal(e),
        }
    }

    async fn delete_inbox(&self, d: DeleteInbox) -> Response {
        if InboxId::from_rik(&d.rik) != d.inbox {
            return err(ErrorCode::Unauthorized, "key does not own this inbox");
        }
        if yo_crypto::rik::verify(&d.rik, &DeleteInbox::signing_bytes(&d.inbox, d.ts), &d.sig).is_err() {
            return err(ErrorCode::Unauthorized, "bad signature");
        }
        if now().abs_diff(d.ts) > 86400 {
            return err(ErrorCode::BadRequest, "request expired; check your clock");
        }
        let (inbox, t) = (d.inbox, now());
        match self.db.run(move |db| db.burn(&inbox, t)).await {
            Ok(()) => {
                info!("burned an inbox");
                Response::Ok
            }
            Err(e) => internal(e),
        }
    }
}
