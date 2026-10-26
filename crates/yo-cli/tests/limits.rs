//! Abuse limits and authorization on the server (SECURITY_REVIEW.md H-1, M-1
//! and the fetch frame-size fix). Each test runs its own server with limits
//! tuned so the behaviour triggers quickly.

use yo_cli::client::{Client, InitOptions};
use yo_cli::net::{Conn, is_code};
use yo_crypto::kdf::KdfParams;
use yo_proto::msg::{ErrorCode, Request, Response, Side};
use yo_proto::tls;
use yo_server::DbPool;
use yo_server::db::Db;
use yo_server::{Config, Registration, Server};
use yo_store::Paths;

struct TestServer {
    addr: String,
    pin: String,
    _dir: tempfile::TempDir,
}

/// Debug logs from both the server and the client, shown only when a test
/// fails (cargo captures them), so a stalled exchange is diagnosable.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "yo_server=debug,yo_cli=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

async fn server_with(tune: impl FnOnce(&mut Config)) -> TestServer {
    init_tracing();
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = tls::generate_cert(vec!["localhost".into()]).unwrap();
    let chain = tls::load_chain(cert.as_bytes()).unwrap();
    let pin = tls::format_pin(&tls::spki_hash(&chain[0]).unwrap());
    let tls_cfg = std::sync::Arc::new(tls::server_config(chain, tls::load_key(key.as_bytes()).unwrap()).unwrap());
    let mut cfg = Config::new("localhost".into(), 0);
    cfg.registration = Registration::Open;
    tune(&mut cfg);
    let db_path = dir.path().join("server.db");
    if cfg.registration == Registration::Token {
        Db::open(&db_path).unwrap().create_token("letmein", 1, "test", 0, false).unwrap();
    }
    let db = DbPool::open(&db_path, 2).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(Server::new(db, &cfg).serve(listener, tls_cfg));
    TestServer { addr, pin, _dir: dir }
}

fn opts(s: &TestServer) -> InitOptions {
    InitOptions {
        server: s.addr.clone(),
        pin: Some(s.pin.clone()),
        token: None,
        passphrase: "test passphrase".into(),
        kdf: KdfParams::INSECURE_TEST,
    }
}

async fn client(s: &TestServer, homes: &mut Vec<tempfile::TempDir>) -> Client {
    let home = tempfile::tempdir().unwrap();
    let c = Client::init(Paths::at(home.path()), opts(s)).await.unwrap();
    homes.push(home);
    c
}

/// A raw protocol connection authenticated as `c`'s device.
async fn raw(c: &Client) -> anyhow::Result<Conn> {
    Conn::connect(&c.paths, &c.cfg, None).await
}

async fn befriend(a: &mut Client, a_calls_b: &str, b: &mut Client, b_calls_a: &str) {
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let opener = a.add_open(a_calls_b, move |code| tx.send(code.to_string()).unwrap());
    let joiner = async {
        let code = rx.await.unwrap();
        b.add_join(b_calls_a, &code).await
    };
    let (ra, rb) = tokio::time::timeout(std::time::Duration::from_secs(120), async { tokio::join!(opener, joiner) })
        .await
        .expect("key exchange did not finish within 120 s");
    if let Err(e) = &rb {
        panic!("joiner failed: {e:#} (opener: {:?})", ra.as_ref().err().map(|e| format!("{e:#}")));
    }
    ra.unwrap();
}

fn big(n: usize, fill: char) -> String {
    std::iter::repeat_n(fill, n).collect()
}

#[tokio::test]
async fn connections_per_device_are_capped() {
    let s = server_with(|c| c.limits.connections_per_device = 2).await;
    let mut homes = Vec::new();
    let alice = client(&s, &mut homes).await; // holds connection #1
    let second = raw(&alice).await.unwrap(); // #2
    let third = raw(&alice).await;
    let e = third.err().expect("third connection refused");
    assert!(is_code(&e, ErrorCode::RateLimited), "{e:#}");
    drop(second);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    raw(&alice).await.expect("slot freed after a connection closes");
}

#[tokio::test]
async fn concurrent_connections_per_ip_are_capped() {
    let s = server_with(|c| c.limits.connections_per_ip = 2).await;
    let mut homes = Vec::new();
    let alice = client(&s, &mut homes).await; // #1 from 127.0.0.1
    let second = raw(&alice).await.unwrap(); // #2
    assert!(raw(&alice).await.is_err(), "third connection from the same IP is dropped before TLS");
    drop(second);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    raw(&alice).await.expect("slot freed");
}

#[tokio::test]
async fn new_connections_per_ip_are_rate_limited() {
    let s = server_with(|c| c.limits.new_connections_per_minute_per_ip = 3).await;
    let mut homes = Vec::new();
    let alice = client(&s, &mut homes).await; // token 1
    let _c2 = raw(&alice).await.unwrap(); // token 2
    let _c3 = raw(&alice).await.unwrap(); // token 3
    assert!(raw(&alice).await.is_err(), "bucket empty: fourth connection in a minute is refused");
}

#[tokio::test]
async fn recipient_queue_quota() {
    let s = server_with(|c| c.limits.queue_mib_per_device = 1).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;

    // ~66 KiB per envelope: the 1 MiB quota fills after ~15 messages.
    let mut accepted = 0;
    let mut refused = None;
    for i in 0..40 {
        match alice.send_text("bob", &big(60_000, char::from(b'a' + (i % 26) as u8)), None).await {
            Ok(_) => accepted += 1,
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    let e = refused.expect("quota should have been hit");
    assert!(is_code(&e, ErrorCode::RateLimited), "{e:#}");
    assert!(e.to_string().contains("queue is full"), "{e:#}");
    assert!((10..=20).contains(&accepted), "accepted {accepted}");

    // Bob drains the queue (over several fetches); every accepted message arrives.
    bob.sync().await.unwrap();
    assert_eq!(bob.take_unread().unwrap().len(), accepted);
    // And alice can send again.
    alice.send_text("bob", "after the drain", None).await.unwrap();
}

#[tokio::test]
async fn sender_hourly_quota() {
    let s = server_with(|c| c.limits.send_mib_per_hour_per_device = 1).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;
    let mut refused = None;
    for _ in 0..40 {
        if let Err(e) = alice.send_text("bob", &big(60_000, 'z'), None).await {
            refused = Some(e);
            break;
        }
    }
    let e = refused.expect("hourly quota should have been hit");
    assert!(is_code(&e, ErrorCode::RateLimited) && e.to_string().contains("hourly"), "{e:#}");
    // The quota is per sender: bob is unaffected.
    bob.send_text("alice", "still fine", None).await.unwrap();
}

#[tokio::test]
async fn mailbox_cap() {
    let s = server_with(|c| c.limits.mailboxes = 1).await;
    let mut homes = Vec::new();
    let alice = client(&s, &mut homes).await;
    let mut conn = raw(&alice).await.unwrap();
    assert!(matches!(conn.call(Request::MailboxOpen).await.unwrap(), Response::Nameplate(_)));
    let e = conn.call(Request::MailboxOpen).await.expect_err("cap reached");
    assert!(is_code(&e, ErrorCode::RateLimited), "{e:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailboxes_are_bound_to_their_participants() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    let eve = client(&s, &mut homes).await;
    let mut eve_conn = raw(&eve).await.unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let opener = alice.add_open("bob", move |code| tx.send(code.to_string()).unwrap());
    let meddle_then_join = async {
        let code = rx.await.unwrap();
        let (nameplate, _) = yo_crypto::invite::parse_code(&code).unwrap();
        assert!(nameplate >= 10_000, "nameplates have at least five digits: {nameplate}");

        // Eve is registered but not a participant: every mailbox operation is refused…
        for req in [
            Request::MailboxPut { nameplate, side: Side::Joiner, msg: vec![1, 2, 3] },
            Request::MailboxPut { nameplate, side: Side::Opener, msg: vec![1, 2, 3] },
            Request::MailboxGet { nameplate, side: Side::Joiner, index: 0 },
            Request::MailboxGet { nameplate, side: Side::Opener, index: 0 },
            Request::MailboxClose { nameplate },
        ] {
            let e = eve_conn.call(req.clone()).await.err().unwrap_or_else(|| panic!("{req:?} should fail"));
            assert!(is_code(&e, ErrorCode::Unauthorized), "{req:?}: {e:#}");
        }
        // …and the real exchange still completes.
        bob.add_join("alice", &code).await
    };
    let (ra, rb) = tokio::join!(opener, meddle_then_join);
    ra.unwrap();
    rb.unwrap();
    assert_eq!(alice.safety_words("bob").unwrap(), bob.safety_words("alice").unwrap());
}

#[tokio::test]
async fn fetch_is_split_into_frame_sized_pages() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;
    // 24 × ~66 KiB ≈ 1.5 MiB queued: more than one fetch page, and more than
    // a single 2 MiB frame could carry together with the sent copies.
    for i in 0..24 {
        alice.send_text("bob", &big(60_000, char::from(b'a' + i as u8)), None).await.unwrap();
    }
    let mut conn = raw(&bob).await.unwrap();
    let first = match conn.call(Request::Fetch).await.unwrap() {
        Response::Envelopes(v) => v,
        r => panic!("{r:?}"),
    };
    assert!(!first.is_empty() && first.len() < 24, "first page has {} envelopes", first.len());
    drop(conn);
    bob.sync().await.unwrap();
    assert_eq!(bob.take_unread().unwrap().len(), 24, "every page is delivered");
}

// ── Phase 2 ──────────────────────────────────────────────────────────────

fn opts_token(s: &TestServer, token: &str) -> InitOptions {
    InitOptions { token: Some(token.into()), ..opts(s) }
}

#[tokio::test]
async fn failed_registrations_are_throttled_per_ip() {
    let s = server_with(|c| {
        c.registration = Registration::Token;
        c.limits.failed_registrations_per_minute_per_ip = 2;
    })
    .await;
    let home = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        let e = Client::init(Paths::at(home.path()), opts_token(&s, "wrong")).await.err().unwrap();
        assert!(e.to_string().contains("token"), "{e:#}");
    }
    let e = Client::init(Paths::at(home.path()), opts_token(&s, "wrong")).await.err().unwrap();
    assert!(is_code(&e, ErrorCode::RateLimited), "third failure is throttled: {e:#}");
    let e = Client::init(Paths::at(home.path()), opts_token(&s, "letmein")).await.err().unwrap();
    assert!(is_code(&e, ErrorCode::RateLimited), "even a valid token waits for the window: {e:#}");
}

fn spki_of(c: &Client) -> [u8; 32] {
    tls::spki_hash(&tls::load_chain_file(&c.paths.tls_cert()).unwrap()[0]).unwrap()
}

fn entry(spki: [u8; 32]) -> yo_proto::msg::DeviceEntry {
    yo_proto::msg::DeviceEntry {
        device: yo_proto::DeviceId::from_spki_hash(&spki),
        curve25519: [1; 32],
        ed25519: [2; 32],
        tls_spki: spki,
        added_at: 0,
    }
}

#[tokio::test]
async fn device_lists_may_only_name_registered_devices() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let alice = client(&s, &mut homes).await;
    let mut conn = raw(&alice).await.unwrap();
    let rik = yo_crypto::rik::Rik::generate();
    let stranger: [u8; 32] = yo_crypto::random();
    let list = yo_proto::msg::DeviceList {
        inbox: rik.inbox(),
        version: 1,
        devices: vec![entry(spki_of(&alice)), entry(stranger)],
    };
    let e = conn
        .call(Request::PutDeviceList(yo_crypto::devices::sign_list(&rik, list)))
        .await
        .expect_err("unregistered device in the list");
    assert!(is_code(&e, ErrorCode::BadRequest) && e.to_string().contains("not registered"), "{e:#}");
    let list = yo_proto::msg::DeviceList { inbox: rik.inbox(), version: 1, devices: vec![entry(spki_of(&alice))] };
    assert!(matches!(
        conn.call(Request::PutDeviceList(yo_crypto::devices::sign_list(&rik, list))).await.unwrap(),
        Response::Ok
    ));
}

#[tokio::test]
async fn unread_counter_ignores_envelopes_for_unknown_inboxes() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    let carol = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;

    // Alice lists bob's (registered) device in an inbox bob knows nothing
    // about, and carol — not a member — sends junk to it.
    let rik = yo_crypto::rik::Rik::generate();
    let list = yo_proto::msg::DeviceList {
        inbox: rik.inbox(),
        version: 1,
        devices: vec![entry(spki_of(&alice)), entry(spki_of(&bob))],
    };
    let mut aconn = raw(&alice).await.unwrap();
    aconn.call(Request::PutDeviceList(yo_crypto::devices::sign_list(&rik, list))).await.unwrap();
    let mut cconn = raw(&carol).await.unwrap();
    let junk = yo_proto::msg::OutEnvelope { device: bob.me, blob: vec![7; 300] };
    cconn.call(Request::Send { inbox: rik.inbox(), envelopes: vec![junk] }).await.unwrap();

    // The daemon path: download without the passphrase, recount.
    let mut bconn = raw(&bob).await.unwrap();
    yo_cli::client::download_to_spool(&mut bconn, &bob.paths).await.unwrap();
    assert_eq!(yo_store::spool::refresh_unread(&bob.paths, None).unwrap(), 0, "junk is not counted");

    // A real message still is.
    alice.send_text("bob", "real", None).await.unwrap();
    yo_cli::client::download_to_spool(&mut bconn, &bob.paths).await.unwrap();
    assert_eq!(yo_store::spool::refresh_unread(&bob.paths, None).unwrap(), 1);
    drop(bconn);
    let r = bob.sync().await.unwrap();
    assert_eq!(r.new_messages, 1);
    assert!(r.notices.iter().all(|n| !n.contains("undecryptable")), "junk is dropped silently: {:?}", r.notices);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linking_needs_the_existing_devices_approval() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let new_home = tempfile::tempdir().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let opener = alice.link_open(move |code| tx.send(code.to_string()).unwrap(), |_| false);
    let joiner = async {
        let code = rx.await.unwrap();
        assert_eq!(code.matches('-').count(), 4, "link codes have four words: {code}");
        Client::init_linked(Paths::at(new_home.path()), opts(&s), &code, |_| {}).await
    };
    let (ra, rb) = tokio::join!(opener, joiner);
    let e = ra.expect_err("declined on the existing device");
    assert!(e.to_string().contains("cancelled"), "{e:#}");
    assert!(rb.is_err(), "the new device gets nothing");
    assert_eq!(alice.devices().await.unwrap().len(), 1);
}

/// Claim keys for `device` in `inbox` until the server hands out the fallback key.
async fn exhaust_one_time_keys(conn: &mut Conn, inbox: yo_proto::InboxId, device: yo_proto::DeviceId) {
    for _ in 0..60 {
        match conn.call(Request::ClaimKey { inbox, device }).await.unwrap() {
            Response::Key(Some(k)) if k.fallback => return,
            Response::Key(Some(_)) => continue,
            r => panic!("{r:?}"),
        }
    }
    panic!("one-time keys never ran out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fallback_key_rotation_keeps_one_previous_key() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;
    let alice_inbox = alice.contact("bob").unwrap().bundle.my_inbox();

    // Bob's first message has to use alice's fallback key.
    let mut bconn = raw(&bob).await.unwrap();
    exhaust_one_time_keys(&mut bconn, alice_inbox, alice.me).await;
    bob.send_text("alice", "via fallback", None).await.unwrap();
    // Alice rotates once before reading: the old key is kept as "previous".
    assert_eq!(alice.rotate_fallback_keys(0).await.unwrap(), 2, "self + bob relationships");
    let r = alice.sync().await.unwrap();
    assert_eq!(r.new_messages, 1, "{:?}", r.notices);
    // The established session keeps working after further rotations.
    alice.rotate_fallback_keys(0).await.unwrap();
    bob.send_text("alice", "same session", None).await.unwrap();
    assert_eq!(alice.sync().await.unwrap().new_messages, 1);

    // A session set up with a key that has since been rotated out twice
    // can no longer be opened: that is the (14-day, in real life) grace
    // period ending.
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let b2_home = tempfile::tempdir().unwrap();
    let b2_opts = opts(&s);
    let linker = bob.link_open(move |code| tx.send(code.to_string()).unwrap(), |_| true);
    let joiner = async {
        let code = rx.await.unwrap();
        Client::init_linked(Paths::at(b2_home.path()), b2_opts, &code, |_| {}).await
    };
    let (_, bob2) = tokio::join!(linker, joiner);
    let mut bob2 = bob2.unwrap();
    exhaust_one_time_keys(&mut bconn, alice_inbox, alice.me).await;
    bob2.send_text("alice", "stale key", None).await.unwrap();
    alice.rotate_fallback_keys(0).await.unwrap();
    alice.rotate_fallback_keys(0).await.unwrap();
    let r = alice.sync().await.unwrap();
    assert_eq!(r.new_messages, 0);
    assert!(r.notices.iter().any(|n| n.contains("undecryptable")), "{:?}", r.notices);
}

// ── Phase 3 ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_deregistration_is_authorized_and_cuts_off_access() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;

    // Link a second device, then remove it from the first.
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let a2_home = tempfile::tempdir().unwrap();
    let a2_opts = opts(&s);
    let linker = alice.link_open(move |code| tx.send(code.to_string()).unwrap(), |_| true);
    let joiner = async {
        let code = rx.await.unwrap();
        Client::init_linked(Paths::at(a2_home.path()), a2_opts, &code, |_| {}).await
    };
    let (_, alice2) = tokio::join!(linker, joiner);
    let alice2 = alice2.unwrap();
    assert_eq!(alice.devices().await.unwrap().len(), 2);

    // alice2 can talk to the server before removal.
    assert!(raw(&alice2).await.is_ok());

    // An outsider cannot deregister alice2 (wrong authority).
    let carol = client(&s, &mut homes).await;
    let mut cconn = raw(&carol).await.unwrap();
    let evil = yo_crypto::rik::Rik::generate();
    let ts = yo_proto::now();
    let sig = evil.sign(&yo_proto::msg::Deregister::signing_bytes(&alice2.me, ts));
    let bad = yo_proto::msg::Deregister { device: alice2.me, ts, authority: evil.public(), sig };
    let e = cconn.call(Request::Deregister(bad)).await.expect_err("outsider refused");
    assert!(is_code(&e, ErrorCode::Unauthorized), "{e:#}");
    assert!(raw(&alice2).await.is_ok(), "alice2 still has access after the bogus attempt");

    // alice removes alice2 → it leaves every device list and its registration
    // is revoked (the lock-out is asserted in token mode below).
    alice.remove_device(&alice2.me.to_string()[..8], false).await.unwrap();
    assert_eq!(alice.devices().await.unwrap().len(), 1);
}

#[tokio::test]
async fn deregistration_requires_the_bound_authority() {
    // A token-mode server: after deregistration the device can't get back in
    // without a new token, which proves access was really cut off.
    let s = server_with(|c| c.registration = Registration::Token).await;
    let home = tempfile::tempdir().unwrap();
    Db::open(&s._dir.path().join("server.db")).unwrap(); // ensure path exists
    // Register one device with the seeded token.
    let alice = Client::init(Paths::at(home.path()), opts_token(&s, "letmein")).await.unwrap();
    // Deregister it using its own bound authority (the self-RIK), as another
    // of its devices would. We can reach the self-RIK through the store.
    let me_rik = {
        let rels = alice.store.relationships().unwrap();
        rels.into_iter().find(|r| r.bundle.kind == yo_store::RelKind::Myself).unwrap().bundle.rik()
    };
    let mut conn = raw(&alice).await.unwrap();
    let ts = yo_proto::now();
    let sig = me_rik.sign(&yo_proto::msg::Deregister::signing_bytes(&alice.me, ts));
    let dereg = yo_proto::msg::Deregister { device: alice.me, ts, authority: me_rik.public(), sig };
    assert!(matches!(conn.call(Request::Deregister(dereg)).await.unwrap(), Response::Ok));
    drop(conn);
    // Now a brand-new connection (new TLS identity would be a new device, but
    // the *same* device reconnecting) is treated as unregistered and, in
    // token mode, refused.
    let e = raw(&alice).await.err().expect("deregistered device is locked out in token mode");
    assert!(is_code(&e, ErrorCode::RegistrationRequired), "{e:#}");
}

#[tokio::test]
async fn additional_pins_are_accepted() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let alice = client(&s, &mut homes).await;
    // The real pin is wrong as `pin`, but listed in `extra_pins`.
    let mut cfg = alice.cfg.clone();
    let real = cfg.pin.take().unwrap();
    cfg.pin = Some(tls::format_pin(&[9u8; 32])); // bogus primary
    cfg.extra_pins = vec![real];
    assert!(Conn::connect(&alice.paths, &cfg, None).await.is_ok(), "a matching extra pin is accepted");
    // Neither pin matching is refused.
    cfg.extra_pins = vec![tls::format_pin(&[8u8; 32])];
    assert!(Conn::connect(&alice.paths, &cfg, None).await.is_err(), "no matching pin is refused");
}

// ── L-3 re-keying ────────────────────────────────────────────────────────

async fn unread_bodies(c: &mut Client) -> Vec<String> {
    let r = c.sync().await.unwrap();
    assert!(r.offline.is_none(), "{:?}", r.offline);
    c.take_unread().unwrap().into_iter().map(|(row, _)| row.msg.body.clone()).collect()
}

async fn link_second_device(s: &TestServer, c: &mut Client) -> (Client, tempfile::TempDir) {
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let home = tempfile::tempdir().unwrap();
    let o = opts(s);
    let path = home.path().to_path_buf();
    let linker = c.link_open(move |code| tx.send(code.to_string()).unwrap(), |_| true);
    let joiner = async {
        let code = rx.await.unwrap();
        Client::init_linked(Paths::at(&path), o, &code, |_| {}).await
    };
    let (_, c2) = tokio::join!(linker, joiner);
    (c2.unwrap(), home)
}

fn self_rik(c: &Client) -> yo_crypto::rik::Rik {
    c.store
        .relationships()
        .unwrap()
        .into_iter()
        .find(|r| r.bundle.kind == yo_store::RelKind::Myself)
        .unwrap()
        .bundle
        .rik()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_device_rotates_every_conversation_key() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;
    let (mut alice2, _h) = link_second_device(&s, &mut alice).await;
    bob.send_text("alice", "before", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["before"]);
    assert_eq!(unread_bodies(&mut alice2).await, vec!["before"]);

    let old_inbox = alice.contact("bob").unwrap().bundle.my_inbox();
    let old_self_inbox = self_rik(&alice).inbox();
    // What a thief with the removed device would hold:
    let stale_rik = alice2.contact("bob").unwrap().bundle.rik();

    alice.remove_device(&alice2.me.to_string()[..8], true).await.unwrap();

    let rel = alice.contact("bob").unwrap();
    assert_ne!(rel.bundle.my_inbox(), old_inbox, "contact key rotated");
    assert_eq!(rel.bundle.prev_inbox, Some(old_inbox));
    assert_ne!(self_rik(&alice).inbox(), old_self_inbox, "device-sync key rotated");

    // The removed device's live connection is cut.
    assert!(alice2.ping().await.is_err(), "deregistered device keeps no live session");

    // Bob picks up the new key on his next sync; both directions work.
    let r = bob.sync().await.unwrap();
    assert!(r.notices.iter().any(|n| n.contains("rotated")), "{:?}", r.notices);
    assert_eq!(bob.contact("alice").unwrap().bundle.peer_inbox(), Some(rel.bundle.my_inbox()));
    bob.send_text("alice", "after", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["after"]);
    alice.send_text("bob", "and back", None).await.unwrap();
    assert_eq!(unread_bodies(&mut bob).await, vec!["and back"]);

    // The thief reconnects (open registration lets it re-register), but the
    // old key cannot touch the new inbox and nothing new is delivered.
    let paths = alice2.paths.clone();
    drop(alice2);
    let dk = Client::unlock(&paths, "test passphrase").unwrap();
    let mut alice2 = Client::open(paths, dk).unwrap();
    let mut a2conn = raw(&alice2).await.unwrap();
    let list =
        yo_proto::msg::DeviceList { inbox: rel.bundle.my_inbox(), version: 2, devices: vec![entry(spki_of(&alice2))] };
    let e = a2conn
        .call(Request::PutDeviceList(yo_crypto::devices::sign_list(&stale_rik, list)))
        .await
        .expect_err("the old key is useless against the new inbox");
    assert!(is_code(&e, ErrorCode::Unauthorized), "{e:#}");
    let r = alice2.sync().await.unwrap();
    assert_eq!(r.new_messages, 0);
    assert!(alice2.take_unread().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contact_who_sends_before_syncing_recovers_after_a_rekey() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;
    alice.rekey_contact("bob").await.unwrap();
    // Bob hasn't synced: his send hits the retired inbox, syncs, and retries.
    bob.send_text("alice", "still works", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["still works"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn messages_queued_before_a_rekey_still_arrive() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let mut bob = client(&s, &mut homes).await;
    befriend(&mut alice, "bob", &mut bob, "alice").await;
    bob.send_text("alice", "in flight", None).await.unwrap(); // queued for the old inbox
    alice.rekey_contact("bob").await.unwrap(); // without reading first
    assert_eq!(unread_bodies(&mut alice).await, vec!["in flight"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rekeying_rotates_the_revocation_authority() {
    let s = server_with(|_| {}).await;
    let mut homes = Vec::new();
    let mut alice = client(&s, &mut homes).await;
    let (mut alice2, _h) = link_second_device(&s, &mut alice).await;
    let old_self = self_rik(&alice);

    alice.rekey_all().await.unwrap();
    let r = alice2.sync().await.unwrap();
    assert!(r.notices.iter().any(|n| n.contains("rotated")), "{:?}", r.notices);
    assert_eq!(self_rik(&alice2).public(), self_rik(&alice).public(), "alice2 adopted the new device-sync key");

    // The old authority can no longer deregister a device…
    let mut conn = raw(&alice).await.unwrap();
    let ts = yo_proto::now();
    let sig = old_self.sign(&yo_proto::msg::Deregister::signing_bytes(&alice2.me, ts));
    let stale = yo_proto::msg::Deregister { device: alice2.me, ts, authority: old_self.public(), sig };
    let e = conn.call(Request::Deregister(stale)).await.expect_err("old authority is refused");
    assert!(is_code(&e, ErrorCode::Unauthorized), "{e:#}");
    // …but a normal removal, signed with the new one, works.
    alice.remove_device(&alice2.me.to_string()[..8], false).await.unwrap();
    assert_eq!(alice.devices().await.unwrap().len(), 1);
}

// ── administration from a client ─────────────────────────────────────────

#[tokio::test]
async fn admins_mint_tokens_from_their_client() {
    let s = server_with(|c| c.registration = Registration::Token).await;
    // The operator's own token grants admin; "letmein" (from the harness) does not.
    Db::open(&s._dir.path().join("server.db")).unwrap().create_token("boss", 1, "operator", 0, true).unwrap();
    let h1 = tempfile::tempdir().unwrap();
    let h2 = tempfile::tempdir().unwrap();
    let mut admin = Client::init(Paths::at(h1.path()), opts_token(&s, "boss")).await.unwrap();
    let mut plain = Client::init(Paths::at(h2.path()), opts_token(&s, "letmein")).await.unwrap();

    // A non-admin device is refused, with a helpful message.
    let e = plain.admin_create_token(1, "x").await.err().expect("not an admin");
    assert!(e.to_string().contains("not an administrator"), "{e:#}");
    assert!(plain.admin_tokens().await.is_err());
    assert!(plain.admin_status().await.is_err());

    // The admin mints a token; the printed line carries server, pin and token.
    let (tok, line) = admin.admin_create_token(1, "alice").await.unwrap();
    assert!(line.starts_with(&format!("yo init --server {}", s.addr)));
    assert!(line.contains(&format!("--pin {}", s.pin)) && line.ends_with(&format!("--token {tok}")));
    let listed = admin.admin_tokens().await.unwrap();
    assert!(listed.iter().any(|t| t.token == tok && t.note == "alice" && !t.grants_admin));

    // The token registers a new device, which is not an admin.
    let h3 = tempfile::tempdir().unwrap();
    let mut alice = Client::init(Paths::at(h3.path()), opts_token(&s, &tok)).await.unwrap();
    assert!(alice.admin_status().await.is_err(), "client-minted tokens never grant admin");
    assert!(!admin.admin_tokens().await.unwrap().iter().any(|t| t.token == tok), "spent tokens disappear");

    // Revoking an unspent token makes it unusable.
    let (tok2, _) = admin.admin_create_token(2, "bob").await.unwrap();
    admin.admin_revoke(&tok2).await.unwrap();
    let h4 = tempfile::tempdir().unwrap();
    assert!(Client::init(Paths::at(h4.path()), opts_token(&s, &tok2)).await.is_err());
    assert!(admin.admin_revoke(&tok2).await.is_err(), "already gone");

    // Status is readable and sane.
    let st = admin.admin_status().await.unwrap();
    assert!(!st.version.is_empty());
    assert_eq!(st.admins, 1);
    assert!(st.registered_devices >= 3, "{st:?}");

    // Bounds and rate limit.
    assert!(admin.admin_create_token(0, "").await.is_err());
    assert!(admin.admin_create_token(101, "").await.is_err());
    let mut limited = false;
    for _ in 0..12 {
        if admin.admin_create_token(1, "spam").await.is_err() {
            limited = true;
            break;
        }
    }
    assert!(limited, "token minting is rate-limited");
}
