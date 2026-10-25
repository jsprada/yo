//! Abuse limits and authorization on the server (SECURITY_REVIEW.md H-1, M-1
//! and the fetch frame-size fix). Each test runs its own server with limits
//! tuned so the behaviour triggers quickly.

use yo_cli::client::{Client, InitOptions};
use yo_cli::net::{Conn, is_code};
use yo_crypto::kdf::KdfParams;
use yo_proto::msg::{ErrorCode, Request, Response, Side};
use yo_proto::tls;
use yo_server::db::Db;
use yo_server::{Config, Registration, Server};
use yo_store::Paths;

struct TestServer {
    addr: String,
    pin: String,
    _dir: tempfile::TempDir,
}

async fn server_with(tune: impl FnOnce(&mut Config)) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = tls::generate_cert(vec!["localhost".into()]).unwrap();
    let chain = tls::load_chain(cert.as_bytes()).unwrap();
    let pin = tls::format_pin(&tls::spki_hash(&chain[0]).unwrap());
    let tls_cfg = std::sync::Arc::new(tls::server_config(chain, tls::load_key(key.as_bytes()).unwrap()).unwrap());
    let db = Db::open(&dir.path().join("server.db")).unwrap();
    let mut cfg = Config::new("localhost".into(), 0);
    cfg.registration = Registration::Open;
    tune(&mut cfg);
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
    let (ra, rb) = tokio::join!(opener, joiner);
    ra.unwrap();
    rb.unwrap();
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
