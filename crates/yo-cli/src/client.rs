//! The yo! client engine: everything except terminal I/O.

use std::fs::File;

use anyhow::{Context, anyhow, bail};
use yo_crypto::devices::{sign_list, verify_list, verify_prekey};
use yo_crypto::invite::{self, Purpose};
use yo_crypto::kdf::KdfParams;
use yo_crypto::olm::OlmState;
use yo_crypto::rik::{self, Rik};
use yo_crypto::{Key32, safety};
use yo_proto::msg::{DeleteInbox, DeviceEntry, DeviceList, ErrorCode, OutEnvelope, Request, Response, Side};
use yo_proto::{DeviceId, InboxId, now, pad, tls};
use yo_store::{
    Bundle, ClientConfig, Direction, KeyFile, MessageKind, MessageRow, Paths, RelKind, Relationship, Store,
    StoredMessage, spool,
};

use crate::net::{Conn, ServerError, is_code};
use crate::payload::{
    AddPayload, Body, ContactSecret, LinkHello, LinkPayload, Payload, SyncEvent, burn_signing_bytes, new_uuid,
};

/// One-time keys published per relationship, and the refill threshold.
const PREKEY_BATCH: usize = 20;
const PREKEY_LOW: u32 = 5;
/// How long an invite code stays usable.
const INVITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// Longest message accepted by `yo send`.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// Names that cannot be used for contacts because they are commands.
pub const RESERVED: &[&str] = &[
    "init", "add", "read", "reply", "history", "contacts", "rename", "burn", "verify", "link", "devices", "unlock",
    "lock", "daemon", "prompt", "status", "sync", "passwd", "help", "me", "version",
];

pub struct InitOptions {
    pub server: String,
    pub pin: Option<String>,
    pub token: Option<String>,
    pub passphrase: String,
    pub kdf: KdfParams,
}

#[derive(Default, Debug)]
pub struct SyncReport {
    /// New messages from other people.
    pub new_messages: usize,
    /// Human-readable things that happened (burns, new contacts from my
    /// other devices, rejected messages).
    pub notices: Vec<String>,
    /// Set when the server could not be reached.
    pub offline: Option<String>,
}

pub struct SendReport {
    pub delivered_to: usize,
    pub skipped: usize,
}

pub struct Client {
    pub paths: Paths,
    pub cfg: ClientConfig,
    pub store: Store,
    conn: Option<Conn>,
    pub me: DeviceId,
    spki: [u8; 32],
    _lock: File,
}

fn lock(paths: &Paths) -> anyhow::Result<File> {
    let f = File::options().create(true).truncate(false).write(true).open(paths.lock())?;
    f.lock().context("waiting for another yo command to finish")?;
    Ok(f)
}

fn device_spki(paths: &Paths) -> anyhow::Result<[u8; 32]> {
    let chain = tls::load_chain_file(&paths.tls_cert()).context("reading device certificate")?;
    Ok(tls::spki_hash(&chain[0])?)
}

/// Contact names: 1–32 characters of letters, digits, `.`, `_`, `-`.
pub fn validate_name(name: &str) -> anyhow::Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        && !name.starts_with('-');
    if !ok {
        bail!("contact names may use letters, digits, '.', '_' and '-' (max 32 characters)");
    }
    if RESERVED.contains(&name.to_ascii_lowercase().as_str()) {
        bail!("'{name}' is a yo command; pick another name for this contact");
    }
    Ok(())
}

impl Client {
    // ── setup ────────────────────────────────────────────────────────────

    /// Open an initialized store with an already-unlocked data key.
    pub fn open(paths: Paths, dk: Key32) -> anyhow::Result<Client> {
        let cfg = ClientConfig::load(&paths)?;
        Self::open_with(paths, cfg, dk)
    }

    fn open_with(paths: Paths, cfg: ClientConfig, dk: Key32) -> anyhow::Result<Client> {
        let lock = lock(&paths)?;
        let store = Store::open(&paths, dk)?;
        let spki = device_spki(&paths)?;
        Ok(Client { me: DeviceId::from_spki_hash(&spki), spki, paths, cfg, store, conn: None, _lock: lock })
    }

    /// Unlock with a passphrase.
    pub fn unlock(paths: &Paths, passphrase: &str) -> anyhow::Result<Key32> {
        Ok(KeyFile::load(&paths.keyfile())?.unlock(passphrase)?)
    }

    /// Create the device identity, register with the server and open the store.
    ///
    /// `config.toml` is written last, by [`Client::finish_setup`], and marks a
    /// completed setup. Leftovers of an interrupted setup are cleared, but an
    /// existing device certificate is reused so the device stays registered
    /// (and doesn't need a second registration token).
    async fn prepare(paths: Paths, opts: &InitOptions) -> anyhow::Result<Client> {
        if paths.config().exists() {
            bail!("yo! is already set up in {}", paths.data_dir.display());
        }
        if let Some(p) = &opts.pin {
            tls::parse_pin(p)?;
        }
        paths.create_dirs()?;
        for leftover in [paths.keyfile(), paths.db(), paths.unread(), paths.unread_db()] {
            let _ = std::fs::remove_file(leftover);
        }
        if let Ok(rd) = std::fs::read_dir(paths.spool()) {
            for e in rd.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        if device_spki(&paths).is_err() || tls::load_key_file(&paths.tls_key()).is_err() {
            let (cert, key) = tls::generate_cert(vec!["yo-device".into()])?;
            yo_store::write_private(&paths.tls_cert(), cert.as_bytes())?;
            yo_store::write_private(&paths.tls_key(), key.as_bytes())?;
        }
        let cfg = ClientConfig { server: opts.server.clone(), pin: opts.pin.clone(), unlock_minutes: 15, banner: true };
        let conn = Conn::connect(&paths, &cfg, opts.token.clone()).await?;
        let (kf, dk) = KeyFile::create(&opts.passphrase, opts.kdf)?;
        kf.save(&paths.keyfile())?;
        let mut c = Client::open_with(paths, cfg, dk)?;
        c.conn = Some(conn);
        Ok(c)
    }

    fn finish_setup(&self) -> anyhow::Result<()> {
        self.cfg.save(&self.paths)?;
        self.refresh_unread();
        Ok(())
    }

    /// `yo init`: a brand-new account on this device.
    pub async fn init(paths: Paths, opts: InitOptions) -> anyhow::Result<Client> {
        let mut c = Self::prepare(paths, &opts).await?;
        c.create_relationship(RelKind::Myself, "me".into(), Rik::generate(), None, true, now()).await?;
        c.finish_setup()?;
        Ok(c)
    }

    /// `yo init --link CODE`: join an existing account from another device.
    pub async fn init_linked(paths: Paths, opts: InitOptions, code: &str) -> anyhow::Result<Client> {
        let (nameplate, code) = invite::parse_code(code)?;
        let mut c = Self::prepare(paths, &opts).await?;
        let hello = postcard::to_stdvec(&LinkHello { device: c.me })?;
        let secret = c.pake_join(Purpose::LinkDevice, nameplate, &code, hello).await?;
        let payload: LinkPayload = postcard::from_bytes(&secret).context("malformed link payload")?;
        c.create_relationship(
            RelKind::Myself,
            "me".into(),
            Rik::from_secret(&payload.self_rik_secret),
            None,
            true,
            now(),
        )
        .await?;
        for cs in &payload.contacts {
            c.join_contact(cs).await?;
        }
        c.finish_setup()?;
        Ok(c)
    }

    async fn conn(&mut self) -> anyhow::Result<&mut Conn> {
        if self.conn.as_ref().is_some_and(|c| c.is_poisoned()) {
            self.conn = None;
        }
        if self.conn.is_none() {
            self.conn = Some(Conn::connect(&self.paths, &self.cfg, None).await?);
        }
        Ok(self.conn.as_mut().expect("just connected"))
    }

    async fn call(&mut self, req: Request) -> anyhow::Result<Response> {
        self.conn().await?.call(req).await
    }

    pub fn refresh_unread(&self) {
        let n = self.store.unread_count().ok();
        let _ = spool::refresh_unread(&self.paths, n);
    }

    // ── relationships ────────────────────────────────────────────────────

    pub fn contacts(&self) -> anyhow::Result<Vec<Relationship>> {
        Ok(self.store.relationships()?.into_iter().filter(|r| r.bundle.kind == RelKind::Contact).collect())
    }

    pub fn contact(&self, name: &str) -> anyhow::Result<Relationship> {
        self.contacts()?
            .into_iter()
            .find(|r| r.bundle.nickname.eq_ignore_ascii_case(name))
            .ok_or_else(|| anyhow!("no contact named '{name}' (see `yo contacts`)"))
    }

    fn myself(&self) -> anyhow::Result<Relationship> {
        self.store
            .relationships()?
            .into_iter()
            .find(|r| r.bundle.kind == RelKind::Myself)
            .ok_or_else(|| anyhow!("account is missing its device-sync relationship"))
    }

    /// Store a new relationship, put this device in its inbox and publish keys.
    async fn create_relationship(
        &mut self,
        kind: RelKind,
        nickname: String,
        rik: Rik,
        peer_rik: Option<[u8; 32]>,
        verified: bool,
        created_at: u64,
    ) -> anyhow::Result<Relationship> {
        let bundle = Bundle {
            kind,
            nickname,
            rik_secret: *rik.secret(),
            rsk: yo_crypto::random(),
            peer_rik,
            verified,
            created_at,
            my_list_version: 0,
            peer_list_version: 0,
            my_devices: vec![],
            peer_devices: vec![],
        };
        let mut olm = OlmState::new();
        let mut rel = self.store.insert_relationship(bundle, &olm)?;
        let res = async {
            self.join_inbox(&mut rel, &olm).await?;
            self.publish_prekeys(&rel, &mut olm, true).await
        }
        .await;
        if let Err(e) = res {
            self.store.shred_relationship(rel.id)?;
            return Err(e);
        }
        Ok(rel)
    }

    async fn join_contact(&mut self, cs: &ContactSecret) -> anyhow::Result<Option<Relationship>> {
        let rik = Rik::from_secret(&cs.rik_secret);
        if self.store.relationships()?.iter().any(|r| r.bundle.my_inbox() == rik.inbox()) {
            return Ok(None);
        }
        match self
            .create_relationship(
                RelKind::Contact,
                cs.nickname.clone(),
                rik,
                Some(cs.peer_rik),
                cs.verified,
                cs.created_at,
            )
            .await
        {
            Ok(r) => Ok(Some(r)),
            // The relationship was burned in the meantime.
            Err(e) if is_code(&e, ErrorCode::Burned) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetch and verify a device list. `Ok(None)` if the inbox does not exist.
    async fn fetch_list(&mut self, inbox: InboxId, pinned: &[u8; 32]) -> anyhow::Result<Option<DeviceList>> {
        match self.call(Request::GetDeviceList { inbox }).await? {
            Response::DeviceList(Some(signed)) => {
                verify_list(&signed, Some(pinned)).context("server returned a device list with a bad signature")?;
                if signed.list.inbox != inbox {
                    bail!("server returned the wrong device list");
                }
                Ok(Some(signed.list))
            }
            Response::DeviceList(None) => Ok(None),
            r => Err(anyhow!("unexpected response {r:?}")),
        }
    }

    async fn join_inbox(&mut self, rel: &mut Relationship, olm: &OlmState) -> anyhow::Result<()> {
        let rik = rel.bundle.rik();
        for _ in 0..5 {
            let cur = self.fetch_list(rik.inbox(), &rik.public()).await?;
            let (version, mut devices) = cur.map(|l| (l.version, l.devices)).unwrap_or((0, vec![]));
            devices.retain(|d| d.device != self.me);
            devices.push(olm.device_entry(self.spki, now()));
            let list = DeviceList { inbox: rik.inbox(), version: version + 1, devices };
            match self.call(Request::PutDeviceList(sign_list(&rik, list.clone()))).await {
                Ok(_) => {
                    rel.bundle.my_list_version = list.version;
                    rel.bundle.my_devices = list.devices;
                    self.store.update_bundle(rel)?;
                    return Ok(());
                }
                Err(e) if is_code(&e, ErrorCode::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
        bail!("could not update the device list (too many concurrent changes)")
    }

    async fn publish_prekeys(&mut self, rel: &Relationship, olm: &mut OlmState, fallback: bool) -> anyhow::Result<()> {
        let inbox = rel.bundle.my_inbox();
        let (one_time, fallback) = olm.prekeys(&inbox, PREKEY_BATCH, fallback);
        // Persist the private halves before the public halves go out.
        self.store.save_olm(rel, olm)?;
        self.call(Request::PublishKeys { inbox, one_time, fallback }).await?;
        Ok(())
    }

    /// Refresh both cached device lists of a relationship, refusing rollbacks.
    async fn refresh_lists(&mut self, rel: &mut Relationship) -> anyhow::Result<()> {
        let mine = rel.bundle.rik().public();
        if let Some(l) = self.fetch_list(rel.bundle.my_inbox(), &mine).await? {
            if l.version < rel.bundle.my_list_version {
                bail!(yo_crypto::CryptoError::Rollback);
            }
            rel.bundle.my_list_version = l.version;
            rel.bundle.my_devices = l.devices;
        }
        if let Some(peer) = rel.bundle.peer_rik
            && let Some(l) = self.fetch_list(InboxId::from_rik(&peer), &peer).await?
        {
            if l.version < rel.bundle.peer_list_version {
                bail!(yo_crypto::CryptoError::Rollback);
            }
            rel.bundle.peer_list_version = l.version;
            rel.bundle.peer_devices = l.devices;
        }
        self.store.update_bundle(rel)?;
        Ok(())
    }

    // ── sending ──────────────────────────────────────────────────────────

    /// Encrypt `payload` for every device of the contact (if `to_peer`) and
    /// every other device of mine in this relationship, and hand it to the
    /// server.
    async fn send_payload(
        &mut self,
        rel: &mut Relationship,
        payload: &Payload,
        to_peer: bool,
    ) -> anyhow::Result<SendReport> {
        let mut last_err = None;
        for _ in 0..2 {
            match self.try_send(rel, payload, to_peer).await {
                Ok(r) => return Ok(r),
                Err(e) if is_code(&e, ErrorCode::Conflict) => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.expect("loop ran"))
    }

    async fn try_send(
        &mut self,
        rel: &mut Relationship,
        payload: &Payload,
        to_peer: bool,
    ) -> anyhow::Result<SendReport> {
        self.refresh_lists(rel).await?;
        let plaintext = pad::pad(&postcard::to_stdvec(payload)?).ok_or_else(|| anyhow!("message too large"))?;
        let mut olm = self.store.load_olm(rel)?;

        let mut targets: Vec<(InboxId, DeviceEntry)> = Vec::new();
        if to_peer && let Some(peer_inbox) = rel.bundle.peer_inbox() {
            targets.extend(rel.bundle.peer_devices.iter().map(|d| (peer_inbox, d.clone())));
        }
        let my_inbox = rel.bundle.my_inbox();
        targets.extend(rel.bundle.my_devices.iter().filter(|d| d.device != self.me).map(|d| (my_inbox, d.clone())));

        let mut batches: Vec<(InboxId, Vec<OutEnvelope>)> = Vec::new();
        let mut skipped = 0;
        for (inbox, dev) in targets {
            if !olm.has_session(&dev.curve25519) {
                let key = match self.call(Request::ClaimKey { inbox, device: dev.device }).await? {
                    Response::Key(Some(k)) => k,
                    _ => {
                        skipped += 1;
                        continue;
                    }
                };
                if verify_prekey(&inbox, &dev, &key).is_err() {
                    skipped += 1;
                    continue;
                }
                olm.start_session(&dev.curve25519, &key.curve25519)?;
            }
            let blob = olm.encrypt(&dev.curve25519, &plaintext)?;
            match batches.iter_mut().find(|(i, _)| *i == inbox) {
                Some((_, v)) => v.push(OutEnvelope { device: dev.device, blob }),
                None => batches.push((inbox, vec![OutEnvelope { device: dev.device, blob }])),
            }
        }
        // Ratchet state must be saved before anything leaves this device.
        self.store.save_olm(rel, &olm)?;

        let mut delivered = 0;
        for (inbox, envelopes) in batches {
            let n = envelopes.len();
            self.call(Request::Send { inbox, envelopes }).await?;
            delivered += n;
        }
        Ok(SendReport { delivered_to: delivered, skipped })
    }

    /// `yo <name> <message>` and `yo reply`.
    pub async fn send_text(
        &mut self,
        name: &str,
        text: &str,
        reply_to: Option<[u8; 16]>,
    ) -> anyhow::Result<(i64, SendReport)> {
        if text.trim().is_empty() {
            bail!("message is empty");
        }
        if text.len() > MAX_MESSAGE {
            bail!("message is longer than {} KiB", MAX_MESSAGE / 1024);
        }
        let mut rel = self.contact(name)?;
        if rel.bundle.peer_rik.is_none() {
            bail!("'{name}' has not finished the key exchange");
        }
        let payload =
            Payload { uuid: new_uuid(), sent_at: now(), body: Body::Text { text: text.to_string(), reply_to } };
        let report = match self.send_payload(&mut rel, &payload, true).await {
            Ok(r) => r,
            Err(e) if is_code(&e, ErrorCode::Burned) => {
                // Pick up a pending burn notice, if there is one.
                let _ = self.sync().await;
                if self.contact(name).is_err() {
                    bail!("{name} burned this conversation; nothing was sent");
                }
                bail!(
                    "the server says this conversation was burned, so nothing was sent. \
                     If {name} burned it, `yo burn {name}` removes your copy too"
                );
            }
            Err(e) => return Err(e),
        };
        if report.delivered_to == 0 && rel.bundle.peer_devices.is_empty() {
            bail!("{name} has no devices that can receive messages right now");
        }
        let stored = StoredMessage {
            uuid: payload.uuid,
            direction: Direction::Out,
            kind: MessageKind::Text,
            sent_at: payload.sent_at,
            received_at: payload.sent_at,
            body: text.to_string(),
            reply_to,
        };
        let id = self.store.insert_message(&rel, &stored, true)?.unwrap_or_default();
        Ok((id, report))
    }

    pub async fn reply(&mut self, number: i64, text: &str) -> anyhow::Result<(String, i64, SendReport)> {
        let rels = self.store.relationships()?;
        let row = self.store.message(&rels, number)?.ok_or_else(|| anyhow!("there is no message #{number}"))?;
        let rel =
            rels.iter().find(|r| r.id == row.rel_id).ok_or_else(|| anyhow!("message #{number} has no contact"))?;
        if rel.bundle.kind != RelKind::Contact {
            bail!("message #{number} is a notice from yo!, not from a contact");
        }
        let name = rel.bundle.nickname.clone();
        let (id, rep) = self.send_text(&name, text, Some(row.msg.uuid)).await?;
        Ok((name, id, rep))
    }

    // ── receiving ────────────────────────────────────────────────────────

    /// Download new envelopes into the spool, then decrypt the spool.
    pub async fn sync(&mut self) -> anyhow::Result<SyncReport> {
        let mut report = SyncReport::default();
        if let Err(e) = self.download().await {
            report.offline = Some(format!("{e:#}"));
        }
        self.process_spool(&mut report).await?;
        self.refresh_unread();
        Ok(report)
    }

    async fn download(&mut self) -> anyhow::Result<()> {
        let paths = self.paths.clone();
        download_to_spool(self.conn().await?, &paths).await?;
        Ok(())
    }

    async fn process_spool(&mut self, report: &mut SyncReport) -> anyhow::Result<()> {
        let mut active: Vec<i64> = Vec::new();
        for (path, env) in spool::list(&self.paths)? {
            match self.process_envelope(&env, report).await {
                Ok(Some(rel_id)) => {
                    if !active.contains(&rel_id) {
                        active.push(rel_id);
                    }
                }
                Ok(None) => {}
                Err(e) => report.notices.push(format!("dropped an undecryptable message: {e:#}")),
            }
            std::fs::remove_file(&path)?;
        }
        // Top up one-time keys where sessions may have consumed them.
        if self.conn.is_some() {
            for id in active {
                if let Some(rel) = self.store.relationship(id)? {
                    let inbox = rel.bundle.my_inbox();
                    if let Ok(Response::KeyCount(n)) = self.call(Request::KeyCount { inbox }).await
                        && n < PREKEY_LOW
                    {
                        let mut olm = self.store.load_olm(&rel)?;
                        let _ = self.publish_prekeys(&rel, &mut olm, false).await;
                    }
                }
            }
        }
        Ok(())
    }

    /// Decrypt and apply one envelope. Returns the relationship it belonged to.
    async fn process_envelope(
        &mut self,
        env: &yo_proto::msg::Envelope,
        report: &mut SyncReport,
    ) -> anyhow::Result<Option<i64>> {
        let Some(mut rel) = self.store.relationships()?.into_iter().find(|r| r.bundle.my_inbox() == env.inbox) else {
            return Ok(None); // conversation no longer exists here
        };
        let mut olm = self.store.load_olm(&rel)?;
        let (sender, padded) = olm.decrypt(&env.blob)?;
        self.store.save_olm(&rel, &olm)?;
        drop(olm);
        let payload: Payload = postcard::from_bytes(pad::unpad(&padded).ok_or_else(|| anyhow!("bad padding"))?)?;

        let mut origin = self.origin(&rel, &sender);
        if origin.is_none() && self.conn().await.is_ok() {
            let _ = self.refresh_lists(&mut rel).await;
            origin = self.origin(&rel, &sender);
        }

        match payload.body {
            Body::Text { text, reply_to } => {
                let direction = match origin {
                    Some(Origin::Peer) => Direction::In,
                    Some(Origin::MyDevice) => Direction::Out,
                    None => bail!("message from a device that is not in the contact's signed device list"),
                };
                let msg = StoredMessage {
                    uuid: payload.uuid,
                    direction,
                    kind: MessageKind::Text,
                    sent_at: payload.sent_at,
                    received_at: now(),
                    body: text,
                    reply_to,
                };
                let inserted = self.store.insert_message(&rel, &msg, direction == Direction::Out)?;
                if inserted.is_some() && direction == Direction::In {
                    report.new_messages += 1;
                }
            }
            Body::Burn { inbox, ts, sig } => {
                let bytes = burn_signing_bytes(&inbox, ts);
                let by_peer = rel
                    .bundle
                    .peer_rik
                    .is_some_and(|p| InboxId::from_rik(&p) == inbox && rik::verify(&p, &bytes, &sig).is_ok());
                let mine = rel.bundle.rik().public();
                let by_me = inbox == rel.bundle.my_inbox() && rik::verify(&mine, &bytes, &sig).is_ok();
                if by_peer {
                    let name = rel.bundle.nickname.clone();
                    self.peer_burned(rel).await?;
                    self.notice(&format!(
                        "💥 {name} burned your conversation. Its messages and keys are gone from this device."
                    ))?;
                    report.notices.push(format!("{name} burned your conversation"));
                    return Ok(None);
                } else if by_me {
                    let name = rel.bundle.nickname.clone();
                    self.store.shred_relationship(rel.id)?;
                    self.notice(&format!("💥 You burned your conversation with {name} from another device."))?;
                    report.notices.push(format!("conversation with {name} burned from another device"));
                    return Ok(None);
                } else {
                    bail!("ignored a burn request with an invalid signature");
                }
            }
            Body::Sync(ev) => {
                if rel.bundle.kind != RelKind::Myself || origin != Some(Origin::MyDevice) {
                    bail!("ignored a sync message that did not come from one of my devices");
                }
                match ev {
                    SyncEvent::ContactAdded(cs) => {
                        let name = cs.nickname.clone();
                        if self.join_contact(&cs).await?.is_some() {
                            report.notices.push(format!("added contact {name} (from another device)"));
                        }
                    }
                    SyncEvent::Renamed { inbox, nickname } => {
                        if let Some(mut r) =
                            self.store.relationships()?.into_iter().find(|r| r.bundle.my_inbox() == inbox)
                        {
                            r.bundle.nickname = nickname;
                            self.store.update_bundle(&r)?;
                        }
                    }
                }
            }
        }
        Ok(Some(rel.id))
    }

    fn origin(&self, rel: &Relationship, curve: &[u8; 32]) -> Option<Origin> {
        if rel.bundle.peer_devices.iter().any(|d| &d.curve25519 == curve) {
            Some(Origin::Peer)
        } else if rel.bundle.my_devices.iter().any(|d| &d.curve25519 == curve && d.device != self.me) {
            Some(Origin::MyDevice)
        } else {
            None
        }
    }

    /// A message from yo! itself, shown by `yo read`.
    fn notice(&mut self, text: &str) -> anyhow::Result<()> {
        let me = self.myself()?;
        let msg = StoredMessage {
            uuid: new_uuid(),
            direction: Direction::In,
            kind: MessageKind::Notice,
            sent_at: now(),
            received_at: now(),
            body: text.to_string(),
            reply_to: None,
        };
        self.store.insert_message(&me, &msg, false)?;
        Ok(())
    }

    /// Mark messages read and return them.
    pub fn take_unread(&mut self) -> anyhow::Result<Vec<(MessageRow, Relationship)>> {
        let rels = self.store.relationships()?;
        let rows = self.store.unread(&rels)?;
        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        self.store.mark_read(&ids)?;
        self.refresh_unread();
        let mut out = Vec::new();
        for row in rows {
            if let Some(rel) = self.store.relationship(row.rel_id)? {
                out.push((row, rel));
            }
        }
        Ok(out)
    }

    /// Look up the text of the message a reply refers to.
    pub fn quoted(&self, rel: &Relationship, uuid: &[u8; 16]) -> Option<MessageRow> {
        let id = self.store.find_by_uuid(rel, uuid).ok()??;
        self.store.message(std::slice::from_ref(rel), id).ok()?
    }

    // ── invites (yo add) ─────────────────────────────────────────────────

    /// `yo add NAME`: show a code and wait for the other person.
    pub async fn add_open(&mut self, name: &str, on_code: impl FnOnce(&str)) -> anyhow::Result<Relationship> {
        self.check_new_name(name).await?;
        let (mut rel, rik_pub) = self.pending_contact(name).await?;
        let payload = postcard::to_stdvec(&AddPayload { rik: rik_pub })?;
        let result = self.pake_open(Purpose::AddContact, on_code, payload).await;
        self.finish_add(&mut rel, result).await?;
        Ok(rel)
    }

    /// `yo add NAME CODE`: use the code the other person gave you.
    pub async fn add_join(&mut self, name: &str, code: &str) -> anyhow::Result<Relationship> {
        self.check_new_name(name).await?;
        let (nameplate, code) = invite::parse_code(code)?;
        let (mut rel, rik_pub) = self.pending_contact(name).await?;
        let payload = postcard::to_stdvec(&AddPayload { rik: rik_pub })?;
        let result = self.pake_join(Purpose::AddContact, nameplate, &code, payload).await;
        self.finish_add(&mut rel, result).await?;
        Ok(rel)
    }

    async fn check_new_name(&mut self, name: &str) -> anyhow::Result<()> {
        validate_name(name)?;
        if let Ok(existing) = self.contact(name) {
            if existing.bundle.peer_rik.is_some() {
                bail!("you already have a contact named '{name}'");
            }
            // Left over from an interrupted `yo add`: discard it.
            let _ = self.delete_inbox(&existing).await;
            self.store.shred_relationship(existing.id)?;
        }
        Ok(())
    }

    /// Create the relationship (and its inbox) *before* the exchange, so the
    /// other side can message us the moment it learns our key.
    async fn pending_contact(&mut self, name: &str) -> anyhow::Result<(Relationship, [u8; 32])> {
        let rik = Rik::generate();
        let public = rik.public();
        let rel = self.create_relationship(RelKind::Contact, name.to_string(), rik, None, false, now()).await?;
        Ok((rel, public))
    }

    async fn finish_add(&mut self, rel: &mut Relationship, result: anyhow::Result<Vec<u8>>) -> anyhow::Result<()> {
        let peer = result.and_then(|bytes| {
            let p: AddPayload = postcard::from_bytes(&bytes).context("malformed invite payload")?;
            if p.rik == rel.bundle.rik().public() {
                bail!("you cannot add yourself");
            }
            Ok(p.rik)
        });
        let peer = match peer {
            Ok(p) => p,
            Err(e) => {
                let _ = self.delete_inbox(rel).await;
                self.store.shred_relationship(rel.id)?;
                return Err(e);
            }
        };
        rel.bundle.peer_rik = Some(peer);
        rel.bundle.verified = true;
        self.store.update_bundle(rel)?;
        let _ = self.refresh_lists(rel).await;

        // Tell my other devices about the new contact.
        let cs = ContactSecret {
            nickname: rel.bundle.nickname.clone(),
            rik_secret: rel.bundle.rik_secret,
            peer_rik: peer,
            verified: true,
            created_at: rel.bundle.created_at,
        };
        self.sync_to_my_devices(SyncEvent::ContactAdded(cs)).await;
        Ok(())
    }

    async fn sync_to_my_devices(&mut self, ev: SyncEvent) {
        if let Ok(mut me) = self.myself() {
            let p = Payload { uuid: new_uuid(), sent_at: now(), body: Body::Sync(ev) };
            let _ = self.send_payload(&mut me, &p, false).await;
        }
    }

    async fn mailbox_wait(
        &mut self,
        nameplate: u32,
        side: Side,
        index: u32,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<Vec<u8>> {
        loop {
            if tokio::time::Instant::now() > deadline {
                let _ = self.call(Request::MailboxClose { nameplate }).await;
                bail!("the invite code expired before the other person used it");
            }
            match self.call(Request::MailboxGet { nameplate, side, index }).await {
                Ok(Response::MailboxMsg(Some(m))) => return Ok(m),
                Ok(Response::MailboxMsg(None)) => continue,
                Ok(r) => bail!("unexpected response {r:?}"),
                Err(e) if is_code(&e, ErrorCode::NotFound) => {
                    bail!("the exchange was aborted — the code was wrong or already used. Start again with a new code")
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Opener side of the PAKE: display the code, then exchange payloads.
    async fn pake_open(
        &mut self,
        purpose: Purpose,
        on_code: impl FnOnce(&str),
        mine: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let nameplate = match self.call(Request::MailboxOpen).await? {
            Response::Nameplate(n) => n,
            r => bail!("unexpected response {r:?}"),
        };
        let code = invite::new_code(nameplate);
        on_code(&code);
        let deadline = tokio::time::Instant::now() + INVITE_TIMEOUT;
        let (pake, m0) = invite::start(&code, purpose);
        self.call(Request::MailboxPut { nameplate, side: Side::Opener, msg: m0 }).await?;
        let theirs0 = self.mailbox_wait(nameplate, Side::Opener, 0, deadline).await?;
        let theirs1 = self.mailbox_wait(nameplate, Side::Opener, 1, deadline).await?;
        let checked = pake.finish(&theirs0).and_then(|keys| {
            if theirs1.len() < 32 {
                return Err(yo_crypto::CryptoError::CodeMismatch);
            }
            keys.check_confirm(Side::Joiner, &theirs1[..32])?;
            let peer = keys.open(Side::Joiner, &theirs1[32..])?;
            Ok((keys, peer))
        });
        let (keys, peer) = match checked {
            Ok(v) => v,
            Err(_) => {
                let _ = self.call(Request::MailboxClose { nameplate }).await;
                bail!("the other side typed a different code — nothing was exchanged. Start again with a new code");
            }
        };
        let mut reply = keys.confirm(Side::Opener).to_vec();
        reply.extend(keys.seal(Side::Opener, &mine));
        self.call(Request::MailboxPut { nameplate, side: Side::Opener, msg: reply }).await?;
        Ok(peer)
    }

    /// Joiner side of the PAKE.
    async fn pake_join(
        &mut self,
        purpose: Purpose,
        nameplate: u32,
        code: &str,
        mine: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        match self.call(Request::MailboxJoin { nameplate }).await {
            Ok(_) => {}
            Err(e) if is_code(&e, ErrorCode::NotFound) => {
                bail!("that code is not valid (expired, mistyped or already used)")
            }
            Err(e) => return Err(e),
        }
        let deadline = tokio::time::Instant::now() + INVITE_TIMEOUT;
        let (pake, m) = invite::start(code, purpose);
        let theirs0 = self.mailbox_wait(nameplate, Side::Joiner, 0, deadline).await?;
        self.call(Request::MailboxPut { nameplate, side: Side::Joiner, msg: m }).await?;
        let keys = pake.finish(&theirs0).map_err(|_| anyhow!("key exchange failed"))?;
        let mut msg = keys.confirm(Side::Joiner).to_vec();
        msg.extend(keys.seal(Side::Joiner, &mine));
        self.call(Request::MailboxPut { nameplate, side: Side::Joiner, msg }).await?;
        let theirs1 = self.mailbox_wait(nameplate, Side::Joiner, 1, deadline).await?;
        let _ = self.call(Request::MailboxClose { nameplate }).await;
        if theirs1.len() < 32 || keys.check_confirm(Side::Opener, &theirs1[..32]).is_err() {
            bail!("the code did not match — nothing was exchanged");
        }
        Ok(keys.open(Side::Opener, &theirs1[32..])?)
    }

    // ── multi-device ─────────────────────────────────────────────────────

    /// `yo link`: show a code that a new device uses with `yo init --link`.
    pub async fn link_open(&mut self, on_code: impl FnOnce(&str)) -> anyhow::Result<DeviceId> {
        let me = self.myself()?;
        let contacts = self
            .contacts()?
            .into_iter()
            .filter_map(|r| {
                Some(ContactSecret {
                    nickname: r.bundle.nickname.clone(),
                    rik_secret: r.bundle.rik_secret,
                    peer_rik: r.bundle.peer_rik?,
                    verified: r.bundle.verified,
                    created_at: r.bundle.created_at,
                })
            })
            .collect();
        let payload = LinkPayload { self_rik_secret: me.bundle.rik_secret, contacts };
        let bytes = yo_crypto::Zeroizing::new(postcard::to_stdvec(&payload)?);
        let hello = self.pake_open(Purpose::LinkDevice, on_code, bytes.to_vec()).await?;
        let hello: LinkHello = postcard::from_bytes(&hello).context("malformed link reply")?;
        Ok(hello.device)
    }

    /// My devices (from the signed list of my device-sync inbox).
    pub async fn devices(&mut self) -> anyhow::Result<Vec<DeviceEntry>> {
        let mut me = self.myself()?;
        self.refresh_lists(&mut me).await?;
        Ok(me.bundle.my_devices.clone())
    }

    /// Remove a device (by id prefix) from every relationship.
    pub async fn remove_device(&mut self, prefix: &str) -> anyhow::Result<DeviceEntry> {
        let devices = self.devices().await?;
        let p = prefix.to_ascii_lowercase();
        let matches: Vec<&DeviceEntry> = devices.iter().filter(|d| d.device.to_string().starts_with(&p)).collect();
        let target = match matches.as_slice() {
            [one] => (*one).clone(),
            [] => bail!("no device starts with '{prefix}' (see `yo devices`)"),
            _ => bail!("'{prefix}' matches several devices; type more characters"),
        };
        if target.device == self.me {
            bail!("you can't remove the device you are using; run this on another device");
        }
        for mut rel in self.store.relationships()? {
            let rik = rel.bundle.rik();
            for _ in 0..5 {
                let Some(cur) = self.fetch_list(rik.inbox(), &rik.public()).await? else { break };
                if !cur.devices.iter().any(|d| d.device == target.device) {
                    break;
                }
                let devices: Vec<DeviceEntry> = cur.devices.into_iter().filter(|d| d.device != target.device).collect();
                let list = DeviceList { inbox: rik.inbox(), version: cur.version + 1, devices };
                match self.call(Request::PutDeviceList(sign_list(&rik, list.clone()))).await {
                    Ok(_) => {
                        rel.bundle.my_list_version = list.version;
                        rel.bundle.my_devices = list.devices;
                        self.store.update_bundle(&rel)?;
                        break;
                    }
                    Err(e) if is_code(&e, ErrorCode::Conflict) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(target)
    }

    // ── contacts ─────────────────────────────────────────────────────────

    pub async fn rename(&mut self, old: &str, new: &str) -> anyhow::Result<()> {
        validate_name(new)?;
        let mut rel = self.contact(old)?;
        if !old.eq_ignore_ascii_case(new) && self.contact(new).is_ok() {
            bail!("you already have a contact named '{new}'");
        }
        rel.bundle.nickname = new.to_string();
        self.store.update_bundle(&rel)?;
        self.sync_to_my_devices(SyncEvent::Renamed { inbox: rel.bundle.my_inbox(), nickname: new.to_string() }).await;
        Ok(())
    }

    pub fn safety_words(&self, name: &str) -> anyhow::Result<Vec<&'static str>> {
        let rel = self.contact(name)?;
        let peer = rel.bundle.peer_rik.ok_or_else(|| anyhow!("key exchange with '{name}' is not finished"))?;
        Ok(safety::safety_words(&rel.bundle.rik().public(), &peer))
    }

    // ── burn ─────────────────────────────────────────────────────────────

    async fn delete_inbox(&mut self, rel: &Relationship) -> anyhow::Result<()> {
        let rik = rel.bundle.rik();
        let inbox = rik.inbox();
        let ts = now();
        let sig = rik.sign(&DeleteInbox::signing_bytes(&inbox, ts));
        self.call(Request::DeleteInbox(DeleteInbox { inbox, ts, rik: rik.public(), sig })).await?;
        Ok(())
    }

    fn burn_payload(rel: &Relationship) -> Payload {
        let rik = rel.bundle.rik();
        let ts = now();
        let inbox = rik.inbox();
        let sig = rik.sign(&burn_signing_bytes(&inbox, ts));
        Payload { uuid: new_uuid(), sent_at: ts, body: Body::Burn { inbox, ts, sig } }
    }

    /// `yo burn NAME`: notify every device on both sides, delete my inbox on
    /// the server, and crypto-shred everything local.
    ///
    /// With `local_only`, skip the network (e.g. offline) and only shred.
    pub async fn burn(&mut self, name: &str, local_only: bool) -> anyhow::Result<Option<SendReport>> {
        let mut rel = self.contact(name)?;
        let mut report = None;
        if !local_only {
            let payload = Self::burn_payload(&rel);
            match self.send_payload(&mut rel, &payload, true).await {
                Ok(r) => report = Some(r),
                // Peer already burned it: still tell my own devices.
                Err(e) if is_code(&e, ErrorCode::Burned) => {
                    report = self.send_payload(&mut rel, &payload, false).await.ok();
                }
                Err(e) => {
                    return Err(e.context(format!(
                        "could not reach the server to tell {name}'s devices. \
                         `yo burn {name} --local` destroys only your copy now"
                    )));
                }
            }
            match self.delete_inbox(&rel).await {
                Ok(()) => {}
                Err(e) if is_code(&e, ErrorCode::Burned) => {}
                Err(e) => return Err(e),
            }
        }
        self.store.shred_relationship(rel.id)?;
        self.refresh_unread();
        Ok(report)
    }

    /// The contact burned the conversation: forward the burn to my other
    /// devices, delete my inbox, shred.
    async fn peer_burned(&mut self, mut rel: Relationship) -> anyhow::Result<()> {
        if self.conn().await.is_ok() {
            let p = Self::burn_payload(&rel);
            let _ = self.send_payload(&mut rel, &p, false).await;
            let _ = self.delete_inbox(&rel).await;
        }
        self.store.shred_relationship(rel.id)?;
        Ok(())
    }

    // ── status ───────────────────────────────────────────────────────────

    pub async fn ping(&mut self) -> anyhow::Result<std::time::Duration> {
        let t = std::time::Instant::now();
        self.call(Request::Ping).await?;
        Ok(t.elapsed())
    }
}

/// Fetch every queued envelope into the spool and acknowledge it. Needs no
/// passphrase: the envelopes stay end-to-end encrypted on disk.
pub async fn download_to_spool(conn: &mut Conn, paths: &Paths) -> anyhow::Result<usize> {
    let mut total = 0;
    loop {
        let envs = match conn.call(Request::Fetch).await? {
            Response::Envelopes(v) => v,
            r => bail!("unexpected response {r:?}"),
        };
        if envs.is_empty() {
            return Ok(total);
        }
        let ids: Vec<u64> = envs.iter().map(|e| e.id).collect();
        for e in &envs {
            spool::write(paths, e)?;
        }
        conn.call(Request::Ack { ids }).await?;
        total += envs.len();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Origin {
    Peer,
    MyDevice,
}

/// Re-export so callers can match on server errors.
pub type ServerErr = ServerError;
