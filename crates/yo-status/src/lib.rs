//! `yo-status`: a tiny read-only HTTPS page that says what yo! is and whether
//! the `yo-server` on this machine is up.
//!
//! It learns the server's state from a local Unix socket (never the network)
//! once a minute, keeps the answer in memory, and serves a static page from
//! that cache. Page views never touch the socket, so the page cannot be used
//! to load the server. There is no JavaScript; the page refreshes itself with
//! a `<meta>` tag.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;

pub fn version_string() -> String {
    let sha = env!("YO_BUILD_SHA");
    if sha.is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        format!("{} ({sha})", env!("CARGO_PKG_VERSION"))
    }
}

// ── configuration ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to serve on (default `[::]:443`).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The yo-server status socket.
    pub status_socket: PathBuf,
    /// Present while an update/restart is in progress → yellow.
    #[serde(default = "default_maintenance")]
    pub maintenance_file: PathBuf,
    #[serde(default = "default_poll")]
    pub poll_seconds: u64,
    /// Shown on the page as the address people put in `yo init`.
    #[serde(default)]
    pub server_address: Option<String>,
    #[serde(default = "default_github")]
    pub github: String,
    pub tls: Tls,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Tls {
    /// Let's Encrypt via TLS-ALPN-01 on the HTTPS port itself (no port 80).
    Acme {
        domains: Vec<String>,
        email: String,
        cache_dir: PathBuf,
        #[serde(default = "yes")]
        production: bool,
    },
    /// Your own certificate chain and key (PEM).
    Files { cert: PathBuf, key: PathBuf },
    /// A self-signed certificate generated at start-up (testing).
    SelfSigned { domains: Vec<String> },
    /// Plain HTTP. Only for local testing.
    None,
}

fn default_listen() -> String {
    "[::]:443".into()
}
fn default_maintenance() -> PathBuf {
    "/run/yo-server-maintenance".into()
}
fn default_poll() -> u64 {
    60
}
fn default_github() -> String {
    "https://github.com/jsprada/yo".into()
}
fn yes() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)?;
        if cfg.poll_seconds == 0 {
            anyhow::bail!("poll_seconds must be at least 1");
        }
        Ok(cfg)
    }
}

// ── the server's answer ───────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
struct ServerStatus {
    version: String,
    protocol: u16,
    started_at: u64,
}

async fn query(socket: &Path) -> anyhow::Result<ServerStatus> {
    let mut stream = tokio::time::timeout(Duration::from_secs(2), tokio::net::UnixStream::connect(socket)).await??;
    let mut buf = Vec::with_capacity(256);
    tokio::time::timeout(Duration::from_secs(2), (&mut stream).take(4096).read_to_end(&mut buf)).await??;
    Ok(serde_json::from_slice(&buf)?)
}

// ── state ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Led {
    Green,
    Yellow,
    Red,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub led: Led,
    pub headline: &'static str,
    pub detail: String,
    /// The running server's version, or the last one seen while it is down.
    pub version: Option<String>,
    pub version_is_last_seen: bool,
    pub protocol: Option<u16>,
    pub started_at: Option<u64>,
    pub maintenance: bool,
    /// When this snapshot was taken (UNIX seconds).
    pub polled_at: u64,
    pub poll_seconds: u64,
}

impl Snapshot {
    pub fn starting(poll_seconds: u64) -> Snapshot {
        Snapshot {
            led: Led::Yellow,
            headline: "Starting",
            detail: "The status page has not polled the server yet.".into(),
            version: None,
            version_is_last_seen: false,
            protocol: None,
            started_at: None,
            maintenance: false,
            polled_at: 0,
            poll_seconds,
        }
    }
}

/// One poll: ask the socket, look for the maintenance marker, decide the LED.
pub async fn poll(socket: &Path, maintenance_file: &Path, prev: &Snapshot) -> Snapshot {
    let maintenance = maintenance_file.exists();
    let now = yo_proto::now();
    match query(socket).await {
        Ok(s) if maintenance => Snapshot {
            led: Led::Yellow,
            headline: "Maintenance in progress",
            detail: "The server is up but an update is being applied; it may restart shortly.".into(),
            version: Some(s.version),
            version_is_last_seen: false,
            protocol: Some(s.protocol),
            started_at: Some(s.started_at),
            maintenance,
            polled_at: now,
            poll_seconds: prev.poll_seconds,
        },
        Ok(s) => Snapshot {
            led: Led::Green,
            headline: "Up and running",
            detail: "The server answered on its local status socket.".into(),
            version: Some(s.version),
            version_is_last_seen: false,
            protocol: Some(s.protocol),
            started_at: Some(s.started_at),
            maintenance,
            polled_at: now,
            poll_seconds: prev.poll_seconds,
        },
        Err(e) => {
            let (led, headline, detail) = if maintenance {
                (Led::Yellow, "Down for maintenance", "An update or restart is in progress. Back shortly.".to_string())
            } else {
                (Led::Red, "Problem", format!("The server did not answer on its status socket ({e})."))
            };
            Snapshot {
                led,
                headline,
                detail,
                version: prev.version.clone(),
                version_is_last_seen: prev.version.is_some(),
                protocol: prev.protocol,
                started_at: None,
                maintenance,
                polled_at: now,
                poll_seconds: prev.poll_seconds,
            }
        }
    }
}

pub type Shared = Arc<RwLock<Snapshot>>;

/// Poll forever, every `cfg.poll_seconds`.
pub async fn poller(cfg: Config, shared: Shared) {
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.poll_seconds));
    loop {
        tick.tick().await;
        let prev = shared.read().await.clone();
        let next = poll(&cfg.status_socket, &cfg.maintenance_file, &prev).await;
        if next.led != prev.led {
            tracing::info!("status: {:?} — {}", next.led, next.headline);
        }
        *shared.write().await = next;
    }
}

// ── page ──────────────────────────────────────────────────────────────────

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn fmt_utc(ts: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "—".into())
}

fn fmt_ago(ts: u64) -> String {
    let d = yo_proto::now().saturating_sub(ts);
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}

fn fmt_uptime(started: u64) -> String {
    let d = yo_proto::now().saturating_sub(started);
    let (days, rem) = (d / 86400, d % 86400);
    let (h, m) = (rem / 3600, (rem % 3600) / 60);
    if days > 0 { format!("{days}d {h}h {m}m") } else { format!("{h}h {m}m") }
}

pub struct PageInfo<'a> {
    pub github: &'a str,
    pub server_address: Option<&'a str>,
}

pub fn render(snap: &Snapshot, info: &PageInfo) -> String {
    let (class, label) = match snap.led {
        Led::Green => ("green", "up"),
        Led::Yellow => ("yellow", "maintenance"),
        Led::Red => ("red", "problem"),
    };
    let version = match (&snap.version, snap.version_is_last_seen) {
        (Some(v), false) => escape(v),
        (Some(v), true) => format!("{} <span class=\"muted\">(last seen)</span>", escape(v)),
        (None, _) => "—".into(),
    };
    let polled = if snap.polled_at == 0 {
        "not yet".to_string()
    } else {
        format!("{} <span class=\"muted\">({})</span>", fmt_utc(snap.polled_at), fmt_ago(snap.polled_at))
    };
    let uptime = snap.started_at.map(fmt_uptime).unwrap_or_else(|| "—".into());
    let protocol = snap.protocol.map(|p| p.to_string()).unwrap_or_else(|| "—".into());
    let server_row = match info.server_address {
        Some(a) => format!("<tr><th>Server</th><td><code>{}</code></td></tr>", escape(a)),
        None => String::new(),
    };
    let github = escape(info.github);
    let detail = escape(&snap.detail);
    let headline = snap.headline;
    let refresh = snap.poll_seconds.max(15);
    let page_version = escape(&version_string());

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{refresh}">
<title>yo! status</title>
<style>
:root {{ color-scheme: light dark; --fg: #1b1b1b; --bg: #fafafa; --muted: #6b6b6b; --card: #fff; --line: #e4e4e4; }}
@media (prefers-color-scheme: dark) {{ :root {{ --fg: #ececec; --bg: #121212; --muted: #9a9a9a; --card: #1c1c1c; --line: #2c2c2c; }} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 32px 16px; font: 16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }}
main {{ max-width: 640px; margin: 0 auto; }}
h1 {{ font-size: 2.2rem; margin: 0 0 4px; letter-spacing: -0.02em; }}
h1 span {{ color: #e2a300; }}
p.lead {{ margin: 0 0 24px; color: var(--muted); }}
.card {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 20px 22px; margin: 18px 0; }}
.status {{ display: flex; align-items: center; gap: 16px; }}
.led {{ width: 22px; height: 22px; border-radius: 50%; flex: none; border: 2px solid rgba(0,0,0,.15); }}
.led.green {{ background: #2ecc71; box-shadow: 0 0 14px #2ecc71aa; }}
.led.yellow {{ background: #f1c40f; box-shadow: 0 0 14px #f1c40faa; }}
.led.red {{ background: #e74c3c; box-shadow: 0 0 14px #e74c3caa; }}
.status strong {{ font-size: 1.15rem; }}
.status .muted, .muted {{ color: var(--muted); }}
table {{ border-collapse: collapse; width: 100%; margin-top: 14px; }}
th, td {{ text-align: left; padding: 7px 0; border-top: 1px solid var(--line); vertical-align: top; }}
th {{ font-weight: 500; color: var(--muted); width: 38%; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .92em; }}
ul {{ padding-left: 20px; margin: 8px 0 0; }}
li {{ margin: 4px 0; }}
a {{ color: inherit; }}
footer {{ margin-top: 28px; font-size: .85rem; color: var(--muted); }}
</style>
</head>
<body>
<main>
<h1>yo<span>!</span></h1>
<p class="lead">Private, end-to-end encrypted messages from your terminal.</p>

<section class="card" aria-live="polite">
  <div class="status">
    <div class="led {class}" role="img" aria-label="status: {label}"></div>
    <div><strong>{headline}</strong><br><span class="muted">{detail}</span></div>
  </div>
  <table>
    <tr><th>Deployed version</th><td>{version}</td></tr>
    <tr><th>Protocol</th><td>{protocol}</td></tr>
    <tr><th>Server uptime</th><td>{uptime}</td></tr>
    {server_row}
    <tr><th>Last checked</th><td>{polled}</td></tr>
  </table>
</section>

<section class="card">
  <p><strong>What is yo!?</strong> A small messenger for the command line.</p>
  <ul>
    <li><strong>End-to-end encrypted.</strong> Messages are encrypted on your device and only decrypted on your contact's. This server relays ciphertext it cannot read.</li>
    <li><strong>Encrypted everywhere:</strong> in transit (mutual TLS), on the server, and on your disk under your passphrase.</li>
    <li><strong>A fresh key for every contact</strong>, so conversations share nothing cryptographically — and either side can burn one.</li>
    <li><strong>Simple:</strong> <code>yo alice "lunch?"</code>, <code>yo read</code>, <code>yo reply 12</code>, and a <code>yo!(3)</code> indicator in your prompt.</li>
  </ul>
  <p>Source, documentation and install instructions: <a href="{github}">{github}</a></p>
</section>

<footer>This page checks the server over a local socket every {poll}s and refreshes itself; it stores nothing and runs no scripts. yo-status {page_version}.</footer>
</main>
</body>
</html>
"#,
        poll = snap.poll_seconds,
    )
}

// ── HTTP ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct App {
    pub shared: Shared,
    pub github: Arc<str>,
    pub server_address: Option<Arc<str>>,
}

fn with_headers(mut resp: Response, content_type: &'static str) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"),
    );
    h.insert("strict-transport-security", HeaderValue::from_static("max-age=31536000"));
    resp
}

async fn index(State(app): State<App>) -> Response {
    let snap = app.shared.read().await.clone();
    let info = PageInfo { github: &app.github, server_address: app.server_address.as_deref() };
    with_headers(render(&snap, &info).into_response(), "text/html; charset=utf-8")
}

async fn status_json(State(app): State<App>) -> Response {
    let snap = app.shared.read().await.clone();
    let body = serde_json::to_string_pretty(&snap).unwrap_or_else(|_| "{}".into());
    with_headers(body.into_response(), "application/json")
}

async fn healthz(State(app): State<App>) -> Response {
    // 200 while the page itself works; the LED, not this, says how the
    // server is. (Monitoring the page shouldn't flap with the server.)
    let _ = app.shared.read().await;
    with_headers("ok\n".into_response(), "text/plain")
}

async fn not_found() -> Response {
    with_headers((StatusCode::NOT_FOUND, "not found\n").into_response(), "text/plain")
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/status.json", get(status_json))
        .route("/healthz", get(healthz))
        .fallback(not_found)
        .with_state(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn fake_server(dir: &Path, version: &str) -> (PathBuf, tokio::task::JoinHandle<()>) {
        let sock = dir.join("status.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let line = format!(
            "{{\"service\":\"yo-server\",\"version\":\"{version}\",\"protocol\":1,\"started_at\":{},\"now\":0}}\n",
            yo_proto::now() - 90
        );
        let h = tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(line.as_bytes()).await;
            }
        });
        (sock, h)
    }

    #[tokio::test]
    async fn led_follows_socket_and_marker() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("maintenance");
        let (sock, server) = fake_server(dir.path(), "0.1.0 (abc1234)").await;
        let start = Snapshot::starting(60);

        let up = poll(&sock, &marker, &start).await;
        assert_eq!(up.led, Led::Green);
        assert_eq!(up.version.as_deref(), Some("0.1.0 (abc1234)"));
        assert!(!up.version_is_last_seen);

        std::fs::write(&marker, "").unwrap();
        let maint_up = poll(&sock, &marker, &up).await;
        assert_eq!(maint_up.led, Led::Yellow);

        server.abort();
        let _ = std::fs::remove_file(&sock);
        let maint_down = poll(&sock, &marker, &maint_up).await;
        assert_eq!(maint_down.led, Led::Yellow);
        assert_eq!(maint_down.headline, "Down for maintenance");

        std::fs::remove_file(&marker).unwrap();
        let down = poll(&sock, &marker, &maint_down).await;
        assert_eq!(down.led, Led::Red);
        assert_eq!(down.version.as_deref(), Some("0.1.0 (abc1234)"), "last seen version is kept");
        assert!(down.version_is_last_seen);
    }

    #[test]
    fn page_escapes_and_shows_state() {
        let mut snap = Snapshot::starting(60);
        snap.led = Led::Red;
        snap.version = Some("<script>alert(1)</script>".into());
        snap.polled_at = yo_proto::now();
        let html = render(
            &snap,
            &PageInfo { github: "https://github.com/jsprada/yo", server_address: Some("yo.example.com:7443") },
        );
        assert!(html.contains(r#"class="led red""#));
        assert!(!html.contains("<script>"), "version is escaped");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("yo.example.com:7443"));
        assert!(!html.contains("<script"), "the page carries no scripts at all");
    }

    #[tokio::test]
    async fn routes_and_headers() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let app = App {
            shared: Arc::new(RwLock::new(Snapshot::starting(60))),
            github: "https://github.com/jsprada/yo".into(),
            server_address: None,
        };
        let r = router(app);
        let resp =
            r.clone().oneshot(axum::http::Request::get("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert!(
            resp.headers().get("content-security-policy").unwrap().to_str().unwrap().contains("default-src 'none'")
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&body).unwrap().contains("yo"));
        let resp = r
            .clone()
            .oneshot(axum::http::Request::get("/status.json").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let resp = r
            .clone()
            .oneshot(axum::http::Request::get("/nope").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
        let resp = r.oneshot(axum::http::Request::post("/").body(axum::body::Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), 405, "read-only: no POST");
    }
}
