//! End-to-end: a real server and several clients talking over mTLS.

use std::path::{Path, PathBuf};

use yo_cli::client::{Client, InitOptions};
use yo_crypto::kdf::KdfParams;
use yo_proto::tls;
use yo_server::db::Db;
use yo_server::{Config, Registration, Server};
use yo_store::{Direction, MessageKind, Paths};

struct TestServer {
    addr: String,
    pin: String,
    db_path: PathBuf,
    _dir: tempfile::TempDir,
}

async fn start_server(registration: Registration) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = tls::generate_cert(vec!["localhost".into()]).unwrap();
    let chain = tls::load_chain(cert.as_bytes()).unwrap();
    let pin = tls::format_pin(&tls::spki_hash(&chain[0]).unwrap());
    let tls_cfg = std::sync::Arc::new(tls::server_config(chain, tls::load_key(key.as_bytes()).unwrap()).unwrap());
    let db_path = dir.path().join("server.db");
    let db = Db::open(&db_path).unwrap();
    let mut cfg = Config::new("localhost".into(), 0);
    cfg.registration = registration;
    if registration == Registration::Token {
        db.create_token("letmein", 1, "test", 0).unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = Server::new(db, &cfg);
    tokio::spawn(server.serve(listener, tls_cfg));
    TestServer { addr, pin, db_path, _dir: dir }
}

fn opts(s: &TestServer, token: Option<&str>) -> InitOptions {
    InitOptions {
        server: s.addr.clone(),
        pin: Some(s.pin.clone()),
        token: token.map(String::from),
        passphrase: "test passphrase".into(),
        kdf: KdfParams::INSECURE_TEST,
    }
}

async fn new_client(s: &TestServer, home: &Path) -> Client {
    Client::init(Paths::at(home), opts(s, None)).await.unwrap()
}

/// Run `yo add` on both sides concurrently.
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

async fn unread_bodies(c: &mut Client) -> Vec<String> {
    let r = c.sync().await.unwrap();
    assert!(r.offline.is_none(), "{:?}", r.offline);
    c.take_unread().unwrap().into_iter().map(|(row, _)| row.msg.body.clone()).collect()
}

fn file_contains(path: &Path, needle: &str) -> bool {
    let mut bytes = std::fs::read(path).unwrap_or_default();
    // Include SQLite's side files if any.
    for ext in ["db-wal", "db-journal"] {
        bytes.extend(std::fs::read(path.with_extension(ext)).unwrap_or_default());
    }
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_lifecycle() {
    let server = start_server(Registration::Open).await;
    let homes: Vec<tempfile::TempDir> = (0..6).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut alice = new_client(&server, homes[0].path()).await;
    let mut bob = new_client(&server, homes[1].path()).await;

    // ── add ──
    befriend(&mut alice, "bob", &mut bob, "alice").await;
    assert_eq!(alice.safety_words("bob").unwrap(), bob.safety_words("alice").unwrap());
    assert!(alice.contact("bob").unwrap().bundle.verified);

    // ── send / read / reply ──
    alice.send_text("bob", "hi bob, zebra crossing at noon", None).await.unwrap();
    let r = bob.sync().await.unwrap();
    assert_eq!(r.new_messages, 1);
    let unread = bob.take_unread().unwrap();
    assert_eq!(unread.len(), 1);
    let (row, rel) = &unread[0];
    assert_eq!(row.msg.body, "hi bob, zebra crossing at noon");
    assert_eq!(rel.bundle.nickname, "alice");
    let number = row.id;
    bob.reply(number, "see you there").await.unwrap();
    let rows = {
        alice.sync().await.unwrap();
        alice.take_unread().unwrap()
    };
    assert_eq!(rows.len(), 1);
    let (reply, arel) = &rows[0];
    assert_eq!(reply.msg.body, "see you there");
    let quoted = alice.quoted(arel, &reply.msg.reply_to.unwrap()).unwrap();
    assert_eq!(quoted.msg.body, "hi bob, zebra crossing at noon");

    // Several messages in a row, both directions.
    for i in 0..3 {
        alice.send_text("bob", &format!("a{i}"), None).await.unwrap();
        bob.send_text("alice", &format!("b{i}"), None).await.unwrap();
    }
    assert_eq!(unread_bodies(&mut bob).await, vec!["a0", "a1", "a2"]);
    assert_eq!(unread_bodies(&mut alice).await, vec!["b0", "b1", "b2"]);

    // ── link a second device for alice ──
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let a2_home = homes[2].path().to_path_buf();
    let a2_opts = opts(&server, None);
    let linker = alice.link_open(move |code| tx.send(code.to_string()).unwrap());
    let new_dev = async move {
        let code = rx.await.unwrap();
        Client::init_linked(Paths::at(&a2_home), a2_opts, &code).await
    };
    let (linked_id, alice2) = tokio::join!(linker, new_dev);
    let mut alice2 = alice2.unwrap();
    assert_eq!(linked_id.unwrap(), alice2.me);
    assert_eq!(alice.devices().await.unwrap().len(), 2);
    assert!(alice2.contact("bob").is_ok(), "contacts are transferred");

    // Bob's message reaches both of alice's devices.
    bob.send_text("alice", "to all your devices", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["to all your devices"]);
    assert_eq!(unread_bodies(&mut alice2).await, vec!["to all your devices"]);

    // alice2 sends; bob gets it and alice's first device gets a sent copy.
    alice2.send_text("bob", "from my laptop", None).await.unwrap();
    assert_eq!(unread_bodies(&mut bob).await, vec!["from my laptop"]);
    alice.sync().await.unwrap();
    let bob_rel = alice.contact("bob").unwrap();
    let hist = alice.store.history(&bob_rel, 50).unwrap();
    let last = hist.last().unwrap();
    assert_eq!(last.msg.body, "from my laptop");
    assert_eq!(last.msg.direction, Direction::Out);

    // ── a third person; contact added on one device syncs to the other ──
    let mut carol = new_client(&server, homes[3].path()).await;
    befriend(&mut carol, "alice", &mut alice, "carol").await;
    let r = alice2.sync().await.unwrap();
    assert!(r.notices.iter().any(|n| n.contains("carol")), "{:?}", r.notices);
    carol.send_text("alice", "carol here", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["carol here"]);
    assert_eq!(unread_bodies(&mut alice2).await, vec!["carol here"]);

    // ── wrong code fails cleanly on both sides ──
    let mut dave = new_client(&server, homes[4].path()).await;
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let opener = alice.add_open("dave", move |code| tx.send(code.to_string()).unwrap());
    let joiner = async {
        let code = rx.await.unwrap();
        let (n, _) = yo_crypto::invite::parse_code(&code).unwrap();
        dave.add_join("alice", &yo_crypto::invite::new_code(n)).await
    };
    let (ra, rd) = tokio::join!(opener, joiner);
    assert!(ra.is_err() && rd.is_err());
    assert!(alice.contact("dave").is_err() && dave.contact("alice").is_err(), "nothing half-added");

    // An interrupted `yo add` (opener gives up before anyone joins) doesn't
    // block adding the same name later.
    let interrupted = tokio::time::timeout(std::time::Duration::from_millis(300), alice.add_open("erin", |_| {})).await;
    assert!(interrupted.is_err(), "still waiting when cancelled");
    let mut erin = new_client(&server, homes[5].path()).await;
    befriend(&mut alice, "erin", &mut erin, "alice").await;
    erin.send_text("alice", "hi from erin", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["hi from erin"]);
    drop(erin);

    // ── bob burns alice ──
    bob.burn("alice", false).await.unwrap();
    assert!(bob.contact("alice").is_err());
    let r = alice.sync().await.unwrap();
    assert!(r.notices.iter().any(|n| n.contains("bob burned")), "{:?}", r.notices);
    assert!(alice.contact("bob").is_err());
    let r = alice2.sync().await.unwrap();
    assert!(r.notices.iter().any(|n| n.contains("bob burned")), "{:?}", r.notices);
    assert!(alice2.contact("bob").is_err());
    // The burn notice is shown by `yo read`.
    let notices: Vec<_> = alice.take_unread().unwrap();
    assert!(notices.iter().any(|(m, _)| m.msg.kind == MessageKind::Notice && m.msg.body.contains("burned")));

    // alice <-> carol still works.
    alice.send_text("carol", "still here?", None).await.unwrap();
    assert_eq!(unread_bodies(&mut carol).await, vec!["still here?"]);
    carol.send_text("alice", "yes!", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["yes!"]);

    // ── remove alice2; carol's messages no longer reach it ──
    let short = alice2.me.to_string()[..8].to_string();
    alice.remove_device(&short).await.unwrap();
    assert_eq!(alice.devices().await.unwrap().len(), 1);
    carol.send_text("alice", "after removal", None).await.unwrap();
    assert_eq!(unread_bodies(&mut alice).await, vec!["after removal"]);
    alice2.sync().await.unwrap();
    assert!(alice2.take_unread().unwrap().iter().all(|(m, _)| m.msg.body != "after removal"));

    // ── nothing readable at rest, anywhere ──
    drop((alice, alice2, bob, carol, dave));
    let mut files = vec![server.db_path.clone()];
    for h in &homes {
        files.push(h.path().join("yo.db"));
        files.push(h.path().join("config.toml"));
        files.push(h.path().join("keyfile"));
    }
    for f in &files {
        for needle in ["zebra", "see you there", "carol here", "alice", "carol", "dave", "from my laptop"] {
            assert!(!file_contains(f, needle), "'{needle}' found in {}", f.display());
        }
    }
}

#[tokio::test]
async fn registration_token_required() {
    let server = start_server(Registration::Token).await;
    let home = tempfile::tempdir().unwrap();
    let err = Client::init(Paths::at(home.path()), opts(&server, None)).await.err().unwrap();
    assert!(format!("{err:#}").contains("token"), "{err:#}");
    assert!(!home.path().join("keyfile").exists(), "failed init leaves nothing behind");
    Client::init(Paths::at(home.path()), opts(&server, Some("letmein"))).await.unwrap();
    // Single-use: a second device can't reuse it.
    let home2 = tempfile::tempdir().unwrap();
    assert!(Client::init(Paths::at(home2.path()), opts(&server, Some("letmein"))).await.is_err());
}

#[tokio::test]
async fn interrupted_setup_can_be_retried() {
    let server = start_server(Registration::Token).await;
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::at(home.path());
    // Simulate a setup that registered (consuming the token) and was then cut
    // off before finishing: the device files and keyfile exist, config doesn't.
    drop(Client::init(paths.clone(), opts(&server, Some("letmein"))).await.unwrap());
    std::fs::remove_file(paths.config()).unwrap();
    // Retrying works without a new token, reusing the registered device.
    let c = Client::init(paths.clone(), opts(&server, None)).await.unwrap();
    assert!(c.contacts().unwrap().is_empty());
    drop(c);
    assert!(Client::init(paths, opts(&server, None)).await.is_err(), "refuses to overwrite a finished setup");
}

#[tokio::test]
async fn wrong_pin_is_refused() {
    let server = start_server(Registration::Open).await;
    let home = tempfile::tempdir().unwrap();
    let mut o = opts(&server, None);
    o.pin = Some(tls::format_pin(&[7u8; 32]));
    let err = Client::init(Paths::at(home.path()), o).await.err().unwrap();
    assert!(format!("{err:#}").contains("pinned"), "{err:#}");
}

#[tokio::test]
async fn wrong_passphrase_is_refused() {
    let server = start_server(Registration::Open).await;
    let home = tempfile::tempdir().unwrap();
    drop(new_client(&server, home.path()).await);
    let paths = Paths::at(home.path());
    assert!(Client::unlock(&paths, "nope").is_err());
    let dk = Client::unlock(&paths, "test passphrase").unwrap();
    Client::open(paths, dk).unwrap();
}
