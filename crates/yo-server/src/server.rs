//! Connection handling and request dispatch.
//!
//! Abuse limits (see `Limits` in `config.rs` and SECURITY_REVIEW.md, H-1):
//! connections are admitted per IP before the TLS handshake and per device
//! after `Hello`; sending is bounded per sender per hour and per recipient
//! queue; invite mailboxes are capped and bound to their participants.

use std::collections::HashMap;
use std::net::IpAddr;
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
use crate::db::{Db, InboxState};
use crate::mailbox::{MailboxError, Mailboxes};

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
type Windows = HashMap<(DeviceId, &'static str), (Instant, u32)>;

struct IpState {
    active: u32,
    tokens: f64,
    refilled: Instant,
}

pub struct Server {
    db: Mutex<Db>,
    mailboxes: Mutex<Mailboxes>,
    subs: Mutex<Subscribers>,
    /// Fixed-window per-device request counters.
    windows: Mutex<Windows>,
    ips: Mutex<HashMap<IpAddr, IpState>>,
    device_conns: Mutex<HashMap<DeviceId, u32>>,
    /// Bytes sent per device in the current hour.
    send_bytes: Mutex<HashMap<DeviceId, (Instant, u64)>>,
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

impl Server {
    pub fn new(db: Db, cfg: &Config) -> Arc<Server> {
        Arc::new(Server {
            db: Mutex::new(db),
            mailboxes: Mutex::new(Mailboxes::new(cfg.limits.mailboxes)),
            subs: Mutex::new(HashMap::new()),
            windows: Mutex::new(HashMap::new()),
            ips: Mutex::new(HashMap::new()),
            device_conns: Mutex::new(HashMap::new()),
            send_bytes: Mutex::new(HashMap::new()),
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
                housekeeping.housekeeping();
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        loop {
            let (tcp, addr) = listener.accept().await?;
            let ip = canonical(addr.ip());
            // Admission per IP happens before any TLS work is done.
            let Some(ip_guard) = self.admit_ip(ip) else {
                debug!("refused connection from {ip}: per-IP limit");
                continue;
            };
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

    fn housekeeping(&self) {
        let n = now();
        let removed = self
            .db
            .lock()
            .expect("db lock")
            .expire(n.saturating_sub(self.ttl_days * 86400), n.saturating_sub(30 * 86400));
        if let Ok(r) = removed
            && r > 0
        {
            info!("expired {r} old records");
        }
        self.mailboxes.lock().expect("mailbox lock").expire();
        self.windows.lock().expect("windows lock").retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
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
        let mut l = self.windows.lock().expect("windows lock");
        let e = l.entry((*device, action)).or_insert((Instant::now(), 0));
        if e.0.elapsed() > Duration::from_secs(60) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        e.1 <= per_minute
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
            Request::Hello { version, token } => self.hello(&device, ip, version, token),
            _ => err(ErrorCode::BadRequest, "expected Hello"),
        };
        let mut _device_guard = None;
        if matches!(resp, Response::Hello { .. }) {
            match self.admit_device(device) {
                Some(g) => _device_guard = Some(g),
                None => resp = err(ErrorCode::RateLimited, "too many open connections from this device"),
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

    fn hello(&self, device: &DeviceId, ip: IpAddr, version: u16, token: Option<String>) -> Response {
        if version != PROTOCOL_VERSION {
            return err(
                ErrorCode::VersionMismatch,
                format!("server speaks protocol {PROTOCOL_VERSION}, client speaks {version}"),
            );
        }
        let db = self.db.lock().expect("db lock");
        match db.is_registered(device) {
            Ok(true) => {}
            Ok(false) => {
                let allowed = match self.registration {
                    Registration::Open => true,
                    Registration::Token => match token {
                        Some(t) => db.use_token(t.trim()).unwrap_or(false),
                        None => false,
                    },
                };
                if !allowed {
                    // Stable wording: fail2ban filters match on it (docs/src/server/setup.md).
                    warn!("registration refused device={} ip={ip}", device.short());
                    return err(
                        ErrorCode::RegistrationRequired,
                        "this server needs a registration token (ask the operator for `yo-server token create`)",
                    );
                }
                if let Err(e) = db.register(device, now()) {
                    return internal(e);
                }
                info!("registered new device {} from {ip}", device.short());
            }
            Err(e) => return internal(e),
        }
        Response::Hello { version: PROTOCOL_VERSION, device: *device }
    }

    async fn request(&self, me: &DeviceId, req: Request) -> Response {
        match req {
            Request::Hello { .. } => err(ErrorCode::BadRequest, "already said hello"),
            Request::Ping | Request::Subscribe => Response::Ok,
            Request::PutDeviceList(list) => self.put_list(me, list),
            Request::GetDeviceList { inbox } => match self.db.lock().expect("db lock").inbox(&inbox) {
                Ok(InboxState::Live { list, .. }) => Response::DeviceList(Some(list)),
                Ok(InboxState::Missing) => Response::DeviceList(None),
                Ok(InboxState::Burned) => err(ErrorCode::Burned, "this conversation was burned"),
                Err(e) => internal(e),
            },
            Request::PublishKeys { inbox, one_time, fallback } => self.publish(me, inbox, one_time, fallback),
            Request::KeyCount { inbox } => match self.db.lock().expect("db lock").key_count(&inbox, me) {
                Ok(n) => Response::KeyCount(n),
                Err(e) => internal(e),
            },
            Request::ClaimKey { inbox, device } => {
                if !self.allow(me, "claim", 120) {
                    return err(ErrorCode::RateLimited, "too many key claims");
                }
                match self.db.lock().expect("db lock").claim_key(&inbox, &device) {
                    Ok(k) => Response::Key(k),
                    Err(e) => internal(e),
                }
            }
            Request::Send { inbox, envelopes } => self.send(me, inbox, envelopes),
            Request::Fetch => match self.db.lock().expect("db lock").fetch(me, FETCH_LIMIT, FETCH_MAX_BYTES) {
                Ok(v) => Response::Envelopes(v),
                Err(e) => internal(e),
            },
            Request::Ack { ids } => match self.db.lock().expect("db lock").ack(me, &ids) {
                Ok(()) => Response::Ok,
                Err(e) => internal(e),
            },
            Request::DeleteInbox(d) => self.delete_inbox(d),
            Request::MailboxOpen => {
                if !self.allow(me, "mailbox", 20) {
                    return err(ErrorCode::RateLimited, "too many invites, wait a minute");
                }
                match self.mailboxes.lock().expect("mailbox lock").open(*me) {
                    Ok(n) => Response::Nameplate(n),
                    Err(_) => err(ErrorCode::RateLimited, "the server is busy with invites; try again in a minute"),
                }
            }
            Request::MailboxJoin { nameplate } => {
                if !self.allow(me, "mailbox", 20) {
                    return err(ErrorCode::RateLimited, "too many invites, wait a minute");
                }
                match self.mailboxes.lock().expect("mailbox lock").join(nameplate, *me) {
                    Ok(()) => Response::Ok,
                    Err(MailboxError::AlreadyJoined) => {
                        err(ErrorCode::Conflict, "that code was already used; ask for a new one")
                    }
                    Err(MailboxError::Unauthorized) => err(ErrorCode::BadRequest, "you can't join your own invite"),
                    Err(_) => err(ErrorCode::NotFound, "no such invite (expired or already used)"),
                }
            }
            Request::MailboxPut { nameplate, side, msg } => {
                if !self.allow(me, "mailbox-io", 240) {
                    return err(ErrorCode::RateLimited, "slow down");
                }
                match self.mailboxes.lock().expect("mailbox lock").put(nameplate, *me, side, msg) {
                    Ok(()) => Response::Ok,
                    Err(MailboxError::TooLarge) => err(ErrorCode::BadRequest, "mailbox message too large"),
                    Err(MailboxError::Unauthorized) => err(ErrorCode::Unauthorized, "not a participant of this invite"),
                    Err(_) => err(ErrorCode::NotFound, "invite closed"),
                }
            }
            Request::MailboxGet { nameplate, side, index } => {
                if !self.allow(me, "mailbox-io", 240) {
                    return err(ErrorCode::RateLimited, "slow down");
                }
                let deadline = tokio::time::Instant::now() + LONG_POLL;
                loop {
                    let got = self.mailboxes.lock().expect("mailbox lock").get(nameplate, *me, side, index);
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
                        self.mailboxes.lock().expect("mailbox lock").get(nameplate, *me, side, index)
                    {
                        return Response::MailboxMsg(Some(m));
                    }
                    if tokio::time::timeout_at(deadline, notified).await.is_err() {
                        return Response::MailboxMsg(None);
                    }
                }
            }
            Request::MailboxClose { nameplate } => {
                match self.mailboxes.lock().expect("mailbox lock").close(nameplate, *me) {
                    Ok(()) | Err(MailboxError::NotFound) => Response::Ok,
                    Err(_) => err(ErrorCode::Unauthorized, "not a participant of this invite"),
                }
            }
        }
    }

    fn put_list(&self, me: &DeviceId, signed: SignedDeviceList) -> Response {
        if let Err(e) = yo_crypto::devices::verify_list(&signed, None) {
            return err(ErrorCode::Unauthorized, e.to_string());
        }
        if signed.list.devices.len() > self.max_devices {
            return err(ErrorCode::BadRequest, format!("at most {} devices per inbox", self.max_devices));
        }
        let mut db = self.db.lock().expect("db lock");
        let in_new = signed.list.devices.iter().any(|d| d.device == *me);
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
                let in_old = list.list.devices.iter().any(|d| d.device == *me);
                if !in_new && !in_old {
                    return err(ErrorCode::Unauthorized, "not a member of this inbox");
                }
            }
        }
        match db.put_list(&signed) {
            Ok(()) => Response::Ok,
            Err(e) => internal(e),
        }
    }

    fn publish(
        &self,
        me: &DeviceId,
        inbox: InboxId,
        one_time: Vec<SignedPreKey>,
        fallback: Option<SignedPreKey>,
    ) -> Response {
        if one_time.len() > MAX_PREKEYS {
            return err(ErrorCode::BadRequest, "too many keys");
        }
        let mut db = self.db.lock().expect("db lock");
        match db.is_member(&inbox, me) {
            Ok(true) => {}
            Ok(false) => return err(ErrorCode::Unauthorized, "not a member of this inbox"),
            Err(e) => return internal(e),
        }
        match db.publish_keys(&inbox, me, &one_time, fallback.as_ref(), MAX_PREKEYS) {
            Ok(()) => Response::Ok,
            Err(e) => internal(e),
        }
    }

    fn send(&self, me: &DeviceId, inbox: InboxId, envelopes: Vec<OutEnvelope>) -> Response {
        if envelopes.len() > MAX_ENVELOPES_PER_SEND || envelopes.iter().any(|e| e.blob.len() > MAX_BLOB) {
            return err(ErrorCode::BadRequest, "message too large");
        }
        if !self.allow(me, "send", self.limits.sends_per_minute) {
            return err(ErrorCode::RateLimited, "slow down");
        }
        let total: u64 = envelopes.iter().map(|e| e.blob.len() as u64).sum();
        if !self.charge_send(me, total) {
            return err(ErrorCode::RateLimited, "hourly sending limit reached; try again later");
        }
        let db = self.db.lock().expect("db lock");
        let list = match db.inbox(&inbox) {
            Ok(InboxState::Live { list, .. }) => list,
            Ok(InboxState::Burned) => return err(ErrorCode::Burned, "this conversation was burned"),
            Ok(InboxState::Missing) => return err(ErrorCode::NotFound, "no such inbox"),
            Err(e) => return internal(e),
        };
        if envelopes.iter().any(|e| !list.list.devices.iter().any(|d| d.device == e.device)) {
            return err(ErrorCode::Conflict, "device list changed; refetch and retry");
        }
        // Per-recipient queue quota, checked for the whole batch before any
        // envelope is stored so a send is all-or-nothing.
        let quota = self.limits.queue_mib_per_device * MIB;
        let mut incoming: HashMap<DeviceId, u64> = HashMap::new();
        for e in &envelopes {
            *incoming.entry(e.device).or_default() += e.blob.len() as u64;
        }
        for (device, add) in &incoming {
            match db.queued_bytes(device) {
                Ok(q) if q + add > quota => {
                    return err(ErrorCode::RateLimited, "a recipient's message queue is full; try again later");
                }
                Ok(_) => {}
                Err(e) => return internal(e),
            }
        }
        let from_member = list.list.devices.iter().any(|d| d.device == *me);
        let ts = now();
        let mut stored = Vec::with_capacity(envelopes.len());
        for e in envelopes {
            match db.insert_envelope(&e.device, &inbox, me, from_member, ts, &e.blob) {
                Ok(env) => stored.push((e.device, env)),
                Err(e) => return internal(e),
            }
        }
        drop(db);
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

    fn delete_inbox(&self, d: DeleteInbox) -> Response {
        if InboxId::from_rik(&d.rik) != d.inbox {
            return err(ErrorCode::Unauthorized, "key does not own this inbox");
        }
        if yo_crypto::rik::verify(&d.rik, &DeleteInbox::signing_bytes(&d.inbox, d.ts), &d.sig).is_err() {
            return err(ErrorCode::Unauthorized, "bad signature");
        }
        if now().abs_diff(d.ts) > 86400 {
            return err(ErrorCode::BadRequest, "request expired; check your clock");
        }
        match self.db.lock().expect("db lock").burn(&d.inbox, now()) {
            Ok(()) => {
                info!("burned an inbox");
                Response::Ok
            }
            Err(e) => internal(e),
        }
    }
}
