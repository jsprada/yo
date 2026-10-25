//! Connection handling and request dispatch.

use std::collections::HashMap;
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

use crate::config::{Config, Registration};
use crate::db::{Db, InboxState};
use crate::mailbox::{MailboxError, Mailboxes};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const LONG_POLL: Duration = Duration::from_secs(25);
const MAX_PREKEYS: usize = 100;
const MAX_ENVELOPES_PER_SEND: usize = 64;
const MAX_BLOB: usize = 300 * 1024;
const FETCH_LIMIT: usize = 200;

type Subscribers = HashMap<DeviceId, Vec<mpsc::UnboundedSender<Envelope>>>;

pub struct Server {
    db: Mutex<Db>,
    mailboxes: Mutex<Mailboxes>,
    subs: Mutex<Subscribers>,
    limits: Mutex<HashMap<(DeviceId, &'static str), (Instant, u32)>>,
    registration: Registration,
    ttl_days: u64,
    max_devices: usize,
}

fn err(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error { code, message: message.into() }
}

fn internal(e: impl std::fmt::Display) -> Response {
    warn!("internal error: {e}");
    err(ErrorCode::Internal, "internal server error")
}

impl Server {
    pub fn new(db: Db, cfg: &Config) -> Arc<Server> {
        Arc::new(Server {
            db: Mutex::new(db),
            mailboxes: Mutex::new(Mailboxes::default()),
            subs: Mutex::new(HashMap::new()),
            limits: Mutex::new(HashMap::new()),
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
            let me = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Err(e) = me.connection(tcp, acceptor).await {
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
        if let Ok(r) = removed {
            if r > 0 {
                info!("expired {r} old records");
            }
        }
        self.mailboxes.lock().expect("mailbox lock").expire();
        self.limits.lock().expect("limits lock").retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
        self.subs.lock().expect("subs lock").retain(|_, v| {
            v.retain(|tx| !tx.is_closed());
            !v.is_empty()
        });
    }

    /// Simple fixed-window rate limit per device and action.
    fn allow(&self, device: &DeviceId, action: &'static str, per_minute: u32) -> bool {
        let mut l = self.limits.lock().expect("limits lock");
        let e = l.entry((*device, action)).or_insert((Instant::now(), 0));
        if e.0.elapsed() > Duration::from_secs(60) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        e.1 <= per_minute
    }

    async fn connection(self: Arc<Self>, tcp: TcpStream, acceptor: TlsAcceptor) -> anyhow::Result<()> {
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
        let resp = match hello {
            Request::Hello { version, token } => self.hello(&device, version, token),
            _ => err(ErrorCode::BadRequest, "expected Hello"),
        };
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

    fn hello(&self, device: &DeviceId, version: u16, token: Option<String>) -> Response {
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
                    return err(
                        ErrorCode::RegistrationRequired,
                        "this server needs a registration token (ask the operator for `yo-server token create`)",
                    );
                }
                if let Err(e) = db.register(device, now()) {
                    return internal(e);
                }
                info!("registered new device {}", device.short());
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
            Request::Fetch => match self.db.lock().expect("db lock").fetch(me, FETCH_LIMIT) {
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
                Response::Nameplate(self.mailboxes.lock().expect("mailbox lock").open())
            }
            Request::MailboxJoin { nameplate } => {
                if !self.allow(me, "mailbox", 20) {
                    return err(ErrorCode::RateLimited, "too many invites, wait a minute");
                }
                match self.mailboxes.lock().expect("mailbox lock").join(nameplate) {
                    Ok(()) => Response::Ok,
                    Err(MailboxError::AlreadyJoined) => {
                        err(ErrorCode::Conflict, "that code was already used; ask for a new one")
                    }
                    Err(_) => err(ErrorCode::NotFound, "no such invite (expired or already used)"),
                }
            }
            Request::MailboxPut { nameplate, side, msg } => {
                match self.mailboxes.lock().expect("mailbox lock").put(nameplate, side, msg) {
                    Ok(()) => Response::Ok,
                    Err(MailboxError::TooLarge) => err(ErrorCode::BadRequest, "mailbox message too large"),
                    Err(_) => err(ErrorCode::NotFound, "invite closed"),
                }
            }
            Request::MailboxGet { nameplate, side, index } => {
                let deadline = tokio::time::Instant::now() + LONG_POLL;
                loop {
                    let got = self.mailboxes.lock().expect("mailbox lock").get(nameplate, side, index);
                    let (msg, notify) = match got {
                        Ok(v) => v,
                        Err(_) => return err(ErrorCode::NotFound, "invite closed"),
                    };
                    if msg.is_some() {
                        return Response::MailboxMsg(msg);
                    }
                    let notified = notify.notified();
                    // Re-check after registering interest to avoid a lost wakeup.
                    if let Ok((Some(m), _)) = self.mailboxes.lock().expect("mailbox lock").get(nameplate, side, index) {
                        return Response::MailboxMsg(Some(m));
                    }
                    if tokio::time::timeout_at(deadline, notified).await.is_err() {
                        return Response::MailboxMsg(None);
                    }
                }
            }
            Request::MailboxClose { nameplate } => {
                self.mailboxes.lock().expect("mailbox lock").close(nameplate);
                Response::Ok
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
        if !self.allow(me, "send", 600) {
            return err(ErrorCode::RateLimited, "slow down");
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
