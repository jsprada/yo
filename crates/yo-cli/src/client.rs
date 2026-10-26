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
    AddPayload, Body, ContactSecret, LinkHello, LinkPayload, Payload, RekeySecret, SyncEvent, burn_signing_bytes,
    new_uuid, rekey_signing_bytes,
};

/// One-time keys published per relationship, and the refill threshold.
const PREKEY_BATCH: usize = 20;
const PREKEY_LOW: u32 = 5;
/// How long an invite code stays usable.
const INVITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// A link code moves account secrets, so it lives for less time.
const LINK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// Rotate the fallback key after this long (it then stays usable as the
/// "previous" key for one more period, so in-flight session setups survive).
const FALLBACK_ROTATE_SECS: u64 = 7 * 86400;
/// …or sooner when one-time keys ran low, which means the fallback key may
/// have been handed out.
const FALLBACK_ROTATE_WHEN_LOW_SECS: u64 = 86400;
/// Longest message accepted by `yo send`. Chosen so that a padded payload
/// fits the 64 KiB bucket: a message to 16 devices then stays well under the
/// 2 MiB frame limit.
pub const MAX_MESSAGE: usize = 64_000;
/// Ciphertext per `Send` request; keeps requests far below `MAX_FRAME`.
const SEND_CHUNK_BYTES: usize = 1024 * 1024;

/// Names that cannot be used for contacts because they are commands.
pub const RESERVED: &[&str] = &[
    "init", "add", "read", "reply", "history", "contacts", "rename", "burn", "verify", "link", "devices", "unlock",
    "lock", "daemon", "prompt", "status", "sync", "passwd", "help", "me", "version", "rekey", "admin",
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
        let cfg = ClientConfig {
            server: opts.server.clone(),
            pin: opts.pin.clone(),
            extra_pins: vec![],
            unlock_minutes: 15,
            banner: true,
        };
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
        let _ = c.bind_revocation(None).await;
        Ok(c)
    }

    /// Tell the server which key may later deregister this device (our own
    /// account's self-identity key). First write wins on the server, so a
    /// stolen device cannot rebind it. Best-effort: retried on later syncs.
    async fn bind_revocation(&mut self, prev: Option<&Rik>) -> anyhow::Result<()> {
        let rik = self.myself()?.bundle.rik();
        let authority = rik.public();
        let bytes = yo_proto::msg::BindRevocation::signing_bytes(&self.me, &authority);
        let sig = rik.sign(&bytes);
        let prev_sig = prev.map(|p| p.sign(&bytes));
        self.call(Request::BindRevocation(yo_proto::msg::BindRevocation { authority, sig, prev_sig })).await?;
        Ok(())
    }

    /// `yo init --link CODE`: join an existing account from another device.
    pub async fn init_linked(
        paths: Paths,
        opts: InitOptions,
        code: &str,
        on_device: impl FnOnce(DeviceId),
    ) -> anyhow::Result<Client> {
        let (nameplate, code) = invite::parse_code(code)?;
        let mut c = Self::prepare(paths, &opts).await?;
        on_device(c.me);
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
        let _ = c.bind_revocation(None).await;
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
        if let Ok(rels) = self.store.relationships() {
            let inboxes: Vec<InboxId> = rels.iter().map(|r| r.bundle.my_inbox()).collect();
            let _ = spool::write_inbox_index(&self.paths, &inboxes);
        }
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
            fallback_at: now(),
            prev_inbox: None,
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
        // Keep the daemon's inbox index current so messages to a brand-new
        // relationship are counted even before the next unlocked command.
        self.refresh_unread();
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

    /// Publish fresh one-time keys and a new fallback key for a relationship.
    async fn rotate_fallback(&mut self, rel: &mut Relationship, olm: &mut OlmState) -> anyhow::Result<()> {
        self.publish_prekeys(rel, olm, true).await?;
        rel.bundle.fallback_at = now();
        Ok(self.store.update_bundle(rel)?)
    }

    /// Rotate the fallback key of every relationship whose key is older than
    /// `older_than_secs`. Returns how many were rotated. Errors (e.g. offline)
    /// are ignored per relationship so one failure doesn't stop the rest.
    pub async fn rotate_fallback_keys(&mut self, older_than_secs: u64) -> anyhow::Result<usize> {
        let mut rotated = 0;
        for mut rel in self.store.relationships()? {
            if now().saturating_sub(rel.bundle.fallback_at) < older_than_secs {
                continue;
            }
            let mut olm = self.store.load_olm(&rel)?;
            if self.rotate_fallback(&mut rel, &mut olm).await.is_ok() {
                rotated += 1;
            }
        }
        Ok(rotated)
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
            // Split big fan-outs so no request approaches the frame limit.
            let mut chunk: Vec<OutEnvelope> = Vec::new();
            let mut bytes = 0;
            for env in envelopes {
                if !chunk.is_empty() && bytes + env.blob.len() > SEND_CHUNK_BYTES {
                    let n = chunk.len();
                    self.call(Request::Send { inbox, envelopes: std::mem::take(&mut chunk) }).await?;
                    delivered += n;
                    bytes = 0;
                }
                bytes += env.blob.len();
                chunk.push(env);
            }
            if !chunk.is_empty() {
                let n = chunk.len();
                self.call(Request::Send { inbox, envelopes: chunk }).await?;
                delivered += n;
            }
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
            bail!("message is longer than {} KB", MAX_MESSAGE / 1000);
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
                // Either the contact burned it, or they rotated keys and the
                // old inbox is gone: sync to find out, then retry once.
                let before = rel.bundle.peer_inbox();
                let _ = self.sync().await;
                match self.contact(name) {
                    Err(_) => bail!("{name} burned this conversation; nothing was sent"),
                    Ok(fresh) if fresh.bundle.peer_inbox() != before => {
                        rel = fresh;
                        self.send_payload(&mut rel, &payload, true).await?
                    }
                    Ok(_) => bail!(
                        "the server says this conversation was burned, so nothing was sent. \
                         If {name} burned it, `yo burn {name}` removes your copy too"
                    ),
                }
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
        if report.offline.is_none() {
            let _ = self.rotate_fallback_keys(FALLBACK_ROTATE_SECS).await;
        }
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
                if let Some(mut rel) = self.store.relationship(id)? {
                    let inbox = rel.bundle.my_inbox();
                    if let Ok(Response::KeyCount(n)) = self.call(Request::KeyCount { inbox }).await
                        && n < PREKEY_LOW
                    {
                        let mut olm = self.store.load_olm(&rel)?;
                        // Running low means the fallback key may be in use:
                        // rotate it too unless it is fresh.
                        if now().saturating_sub(rel.bundle.fallback_at) > FALLBACK_ROTATE_WHEN_LOW_SECS {
                            let _ = self.rotate_fallback(&mut rel, &mut olm).await;
                        } else {
                            let _ = self.publish_prekeys(&rel, &mut olm, false).await;
                        }
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
        let Some(mut rel) = self
            .store
            .relationships()?
            .into_iter()
            .find(|r| r.bundle.my_inbox() == env.inbox || r.bundle.prev_inbox == Some(env.inbox))
        else {
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
            Body::Rekey { old_inbox, new_rik, ts, sig_old, sig_new } => {
                // Copies from my own devices carry no secret; the device-sync
                // event does. Only a contact's announcement is acted on.
                if origin != Some(Origin::MyDevice) {
                    let Some(peer) = rel.bundle.peer_rik else { bail!("re-key for an unfinished contact") };
                    let bytes = rekey_signing_bytes(&old_inbox, &new_rik, ts);
                    let genuine = InboxId::from_rik(&peer) == old_inbox
                        && rik::verify(&peer, &bytes, &sig_old).is_ok()
                        && rik::verify(&new_rik, &bytes, &sig_new).is_ok();
                    if !genuine {
                        bail!("ignored a re-key announcement with an invalid signature");
                    }
                    rel.bundle.peer_rik = Some(new_rik);
                    rel.bundle.peer_list_version = 0;
                    rel.bundle.peer_devices = vec![];
                    self.store.update_bundle(&rel)?;
                    let _ = self.refresh_lists(&mut rel).await;
                    report.notices.push(format!("{} rotated their keys", rel.bundle.nickname));
                }
            }
            Body::Sync(ev) => {
                if rel.bundle.kind != RelKind::Myself || origin != Some(Origin::MyDevice) {
                    bail!("ignored a sync message that did not come from one of my devices");
                }
                match ev {
                    SyncEvent::Rekeyed(secret) => {
                        if let Some(mut r) =
                            self.store.relationships()?.into_iter().find(|r| r.bundle.my_inbox() == secret.old_inbox)
                        {
                            let old_rik = r.bundle.rik();
                            r.bundle.rik_secret = secret.new_rik_secret;
                            r.bundle.prev_inbox = Some(secret.old_inbox);
                            r.bundle.my_list_version = 0;
                            r.bundle.my_devices = vec![];
                            self.store.update_bundle(&r)?;
                            let _ = self.refresh_lists(&mut r).await;
                            // My keys were published under the old inbox id.
                            let mut olm = self.store.load_olm(&r)?;
                            let _ = self.rotate_fallback(&mut r, &mut olm).await;
                            if r.bundle.kind == RelKind::Myself {
                                let _ = self.bind_revocation(Some(&old_rik)).await;
                            }
                            self.refresh_unread();
                            report
                                .notices
                                .push(format!("keys for {} rotated (from another device)", r.bundle.nickname));
                        }
                    }
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
        let result = self.pake_open(Purpose::AddContact, on_code, payload, |_| true).await;
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
                Ok(Response::MailboxMsg(Some(m))) => {
                    tracing::debug!(nameplate, ?side, index, "mailbox: got message");
                    return Ok(m);
                }
                Ok(Response::MailboxMsg(None)) => {
                    tracing::debug!(nameplate, ?side, index, "mailbox: still waiting");
                    continue;
                }
                Ok(r) => bail!("unexpected response {r:?}"),
                Err(e) if is_code(&e, ErrorCode::NotFound) => {
                    bail!("the exchange was aborted — the code was wrong or already used. Start again with a new code")
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Opener side of the PAKE: display the code, then exchange payloads.
    ///
    /// `confirm` sees the other side's decrypted payload *before* ours is
    /// sent; returning false aborts without revealing anything.
    async fn pake_open(
        &mut self,
        purpose: Purpose,
        on_code: impl FnOnce(&str),
        mine: Vec<u8>,
        confirm: impl FnOnce(&[u8]) -> bool,
    ) -> anyhow::Result<Vec<u8>> {
        let nameplate = match self.call(Request::MailboxOpen).await? {
            Response::Nameplate(n) => n,
            r => bail!("unexpected response {r:?}"),
        };
        let (words, ttl) = match purpose {
            Purpose::AddContact => (invite::CODE_WORDS, INVITE_TIMEOUT),
            Purpose::LinkDevice => (invite::LINK_CODE_WORDS, LINK_TIMEOUT),
        };
        let code = invite::new_code_with(nameplate, words);
        tracing::debug!(nameplate, ?purpose, "exchange: opened");
        on_code(&code);
        let deadline = tokio::time::Instant::now() + ttl;
        let (pake, m0) = invite::start(&code, purpose);
        self.call(Request::MailboxPut { nameplate, side: Side::Opener, msg: m0 }).await?;
        tracing::debug!(nameplate, "exchange: opener put message 0");
        let theirs0 = self.mailbox_wait(nameplate, Side::Opener, 0, deadline).await?;
        let theirs1 = self.mailbox_wait(nameplate, Side::Opener, 1, deadline).await?;
        tracing::debug!(nameplate, "exchange: opener has both joiner messages");
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
        if !confirm(&peer) {
            let _ = self.call(Request::MailboxClose { nameplate }).await;
            bail!("cancelled — nothing was sent to the other side");
        }
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
        let ttl = if purpose == Purpose::LinkDevice { LINK_TIMEOUT } else { INVITE_TIMEOUT };
        let deadline = tokio::time::Instant::now() + ttl;
        let (pake, m) = invite::start(code, purpose);
        tracing::debug!(nameplate, ?purpose, "exchange: joined");
        let theirs0 = self.mailbox_wait(nameplate, Side::Joiner, 0, deadline).await?;
        self.call(Request::MailboxPut { nameplate, side: Side::Joiner, msg: m }).await?;
        tracing::debug!(nameplate, "exchange: joiner put message 0");
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
    ///
    /// `confirm` is shown the joining device's id and decides whether the
    /// account secrets are sent to it.
    pub async fn link_open(
        &mut self,
        on_code: impl FnOnce(&str),
        confirm: impl FnOnce(DeviceId) -> bool,
    ) -> anyhow::Result<DeviceId> {
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
        let hello = self
            .pake_open(Purpose::LinkDevice, on_code, bytes.to_vec(), |hello| {
                postcard::from_bytes::<LinkHello>(hello).map(|h| confirm(h.device)).unwrap_or(false)
            })
            .await?;
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
    pub async fn remove_device(&mut self, prefix: &str, rekey: bool) -> anyhow::Result<DeviceEntry> {
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
        // Turn off the removed device's server access as well as taking it out
        // of the device lists. Best-effort: it only works if that device bound
        // a revocation authority at setup (SECURITY_REVIEW.md L-3).
        if let Ok(me_rel) = self.myself() {
            let rik = me_rel.bundle.rik();
            let ts = now();
            let sig = rik.sign(&yo_proto::msg::Deregister::signing_bytes(&target.device, ts));
            let dereg = yo_proto::msg::Deregister { device: target.device, ts, authority: rik.public(), sig };
            let _ = self.call(Request::Deregister(dereg)).await;
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
        if rekey {
            // The removed device still holds every conversation's identity
            // key; rotating them is what finally makes those copies useless.
            self.rekey_all().await?;
        }
        Ok(target)
    }

    // ── re-keying (SECURITY_REVIEW.md L-3) ───────────────────────────────

    /// `yo rekey NAME`: rotate the identity key of one conversation.
    pub async fn rekey_contact(&mut self, name: &str) -> anyhow::Result<()> {
        let mut rel = self.contact(name)?;
        if rel.bundle.peer_rik.is_none() {
            bail!("'{name}' has not finished the key exchange");
        }
        self.rekey_relationship(&mut rel).await
    }

    /// `yo rekey --all`: every conversation, then the device-sync key.
    /// Returns how many keys were rotated.
    pub async fn rekey_all(&mut self) -> anyhow::Result<usize> {
        let mut n = 0;
        for mut rel in self.contacts()? {
            if rel.bundle.peer_rik.is_none() {
                continue;
            }
            self.rekey_relationship(&mut rel).await?;
            n += 1;
        }
        let mut me = self.myself()?;
        self.rekey_relationship(&mut me).await?;
        Ok(n + 1)
    }

    /// Replace a relationship's identity key with a fresh one.
    ///
    /// 1. open a new inbox (listing my current devices) and publish keys there;
    /// 2. announce the new public key to the contact, signed by old and new;
    /// 3. hand the new secret to my other devices over device sync;
    /// 4. switch locally, rebinding this device's revocation authority if
    ///    this was the device-sync key;
    /// 5. retire the old inbox (what was queued there still arrives).
    async fn rekey_relationship(&mut self, rel: &mut Relationship) -> anyhow::Result<()> {
        let _ = self.refresh_lists(rel).await;
        let old_rik = rel.bundle.rik();
        let old_inbox = old_rik.inbox();
        let new_rik = Rik::generate();
        let new_inbox = new_rik.inbox();
        let ts = now();

        let mut olm = self.store.load_olm(rel)?;
        let mut devices = rel.bundle.my_devices.clone();
        if !devices.iter().any(|d| d.device == self.me) {
            devices.push(olm.device_entry(self.spki, ts));
        }
        let list = DeviceList { inbox: new_inbox, version: 1, devices };
        self.call(Request::PutDeviceList(sign_list(&new_rik, list.clone()))).await?;
        // One-time keys are signed over the inbox id, so publish a fresh set.
        let (one_time, fallback) = olm.prekeys(&new_inbox, PREKEY_BATCH, true);
        self.store.save_olm(rel, &olm)?;
        drop(olm);
        self.call(Request::PublishKeys { inbox: new_inbox, one_time, fallback }).await?;

        if rel.bundle.kind == RelKind::Contact {
            let bytes = rekey_signing_bytes(&old_inbox, &new_rik.public(), ts);
            let body = Body::Rekey {
                old_inbox,
                new_rik: new_rik.public(),
                ts,
                sig_old: old_rik.sign(&bytes),
                sig_new: new_rik.sign(&bytes),
            };
            self.send_payload(rel, &Payload { uuid: new_uuid(), sent_at: ts, body }, true).await?;
        }

        let secret = RekeySecret { old_inbox, new_rik_secret: *new_rik.secret() };
        if rel.bundle.kind == RelKind::Myself {
            // Over the *old* device-sync channel, before switching it.
            let p = Payload { uuid: new_uuid(), sent_at: ts, body: Body::Sync(SyncEvent::Rekeyed(secret)) };
            let _ = self.send_payload(rel, &p, false).await;
        } else {
            self.sync_to_my_devices(SyncEvent::Rekeyed(secret)).await;
        }

        rel.bundle.rik_secret = *new_rik.secret();
        rel.bundle.prev_inbox = Some(old_inbox);
        rel.bundle.my_list_version = list.version;
        rel.bundle.my_devices = list.devices;
        rel.bundle.fallback_at = ts;
        self.store.update_bundle(rel)?;
        self.refresh_unread();

        if rel.bundle.kind == RelKind::Myself {
            let _ = self.bind_revocation(Some(&old_rik)).await;
        }

        let sig = old_rik.sign(&DeleteInbox::signing_bytes(&old_inbox, ts));
        let _ = self.call(Request::DeleteInbox(DeleteInbox { inbox: old_inbox, ts, rik: old_rik.public(), sig })).await;
        Ok(())
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

    // ── administration ───────────────────────────────────────────────────

    fn admin_error(e: anyhow::Error) -> anyhow::Error {
        if is_code(&e, ErrorCode::Unauthorized) {
            anyhow!(
                "this device is not an administrator of the server. The operator can make it one with \
                 `yo-server admin grant <device-id>` (your id is shown by `yo status`)"
            )
        } else if e.downcast_ref::<yo_proto::frame::FrameError>().is_some()
            || e.to_string().contains("connection closed")
        {
            anyhow!("the server did not understand that request; it probably needs updating (yo-server-update)")
        } else {
            e
        }
    }

    /// Mint a token. Returns `(token, full yo init line)`.
    pub async fn admin_create_token(&mut self, uses: u32, note: &str) -> anyhow::Result<(String, String)> {
        let token = match self.call(Request::AdminCreateToken { uses, note: note.to_string() }).await {
            Ok(Response::Token(t)) => t,
            Ok(r) => bail!("unexpected response {r:?}"),
            Err(e) => return Err(Self::admin_error(e)),
        };
        let mut line = format!("yo init --server {}", self.cfg.server);
        if let Some(p) = &self.cfg.pin {
            line.push_str(&format!(" --pin {p}"));
        }
        line.push_str(&format!(" --token {token}"));
        Ok((token, line))
    }

    pub async fn admin_tokens(&mut self) -> anyhow::Result<Vec<yo_proto::msg::TokenInfo>> {
        match self.call(Request::AdminListTokens).await {
            Ok(Response::Tokens(t)) => Ok(t),
            Ok(r) => bail!("unexpected response {r:?}"),
            Err(e) => Err(Self::admin_error(e)),
        }
    }

    pub async fn admin_revoke(&mut self, token: &str) -> anyhow::Result<()> {
        match self.call(Request::AdminRevokeToken { token: token.trim().to_string() }).await {
            Ok(_) => Ok(()),
            Err(e) if is_code(&e, ErrorCode::NotFound) => bail!("no such token (already used, or mistyped)"),
            Err(e) => Err(Self::admin_error(e)),
        }
    }

    pub async fn admin_status(&mut self) -> anyhow::Result<yo_proto::msg::AdminStatus> {
        match self.call(Request::AdminStatus).await {
            Ok(Response::AdminStatus(s)) => Ok(s),
            Ok(r) => bail!("unexpected response {r:?}"),
            Err(e) => Err(Self::admin_error(e)),
        }
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
