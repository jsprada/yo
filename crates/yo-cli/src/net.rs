//! A TLS connection to the yo! server.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use yo_proto::frame::FramedConn;
use yo_proto::msg::{Envelope, ErrorCode, Event, Request, Response, ServerFrame};
use yo_proto::tls::{self, ServerTrust};
use yo_proto::{DeviceId, PROTOCOL_VERSION};
use yo_store::{ClientConfig, Paths};

/// An error response from the server.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ServerError {
    pub code: ErrorCode,
    pub message: String,
}

pub fn is_code(e: &anyhow::Error, code: ErrorCode) -> bool {
    e.downcast_ref::<ServerError>().is_some_and(|s| s.code == code)
}

/// Upper bound on one request/response round trip.
const CALL_TIMEOUT: Duration = Duration::from_secs(90);

/// The variant name, for logs and errors (never the payload).
fn request_name(req: &Request) -> &'static str {
    match req {
        Request::Hello { .. } => "Hello",
        Request::PutDeviceList(_) => "PutDeviceList",
        Request::GetDeviceList { .. } => "GetDeviceList",
        Request::PublishKeys { .. } => "PublishKeys",
        Request::KeyCount { .. } => "KeyCount",
        Request::ClaimKey { .. } => "ClaimKey",
        Request::Send { .. } => "Send",
        Request::Fetch => "Fetch",
        Request::Ack { .. } => "Ack",
        Request::Subscribe => "Subscribe",
        Request::DeleteInbox(_) => "DeleteInbox",
        Request::MailboxOpen => "MailboxOpen",
        Request::MailboxJoin { .. } => "MailboxJoin",
        Request::MailboxPut { .. } => "MailboxPut",
        Request::MailboxGet { .. } => "MailboxGet",
        Request::MailboxClose { .. } => "MailboxClose",
        Request::Ping => "Ping",
        Request::BindRevocation(_) => "BindRevocation",
        Request::Deregister(_) => "Deregister",
    }
}

pub struct Conn {
    framed: FramedConn<TlsStream<TcpStream>>,
    events: VecDeque<Envelope>,
    pub device: DeviceId,
    /// Set while a request awaits its response. If a call is cancelled
    /// mid-flight the response would be read by the *next* call, so such a
    /// connection must be discarded (see [`Conn::is_poisoned`]).
    in_flight: bool,
}

/// Split `host:port`, accepting `[v6]:port` and a missing port.
pub fn split_host(server: &str) -> (String, u16) {
    let s = server.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            return (h.to_string(), p.parse().unwrap_or(yo_proto::DEFAULT_PORT));
        }
        return (rest.trim_end_matches(']').to_string(), yo_proto::DEFAULT_PORT);
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(yo_proto::DEFAULT_PORT)),
        _ => (s.to_string(), yo_proto::DEFAULT_PORT),
    }
}

impl Conn {
    pub async fn connect(paths: &Paths, cfg: &ClientConfig, token: Option<String>) -> anyhow::Result<Conn> {
        let chain = tls::load_chain_file(&paths.tls_cert()).context("reading device certificate")?;
        let key = tls::load_key_file(&paths.tls_key()).context("reading device key")?;
        let pins = cfg.all_pins();
        let trust = if pins.is_empty() {
            ServerTrust::WebPki
        } else {
            let parsed: Result<Vec<_>, _> = pins.iter().map(|p| tls::parse_pin(p)).collect();
            ServerTrust::Pinned(parsed?)
        };
        let tls_cfg = Arc::new(tls::client_config(chain, key, trust)?);
        let (host, port) = split_host(&cfg.server);
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| anyhow!("timed out connecting to {}", cfg.server))?
            .with_context(|| format!("cannot reach {}", cfg.server))?;
        tcp.set_nodelay(true)?;
        let stream = TlsConnector::from(tls_cfg).connect(tls::server_name(&host)?, tcp).await.map_err(|e| {
            if e.to_string().contains("ApplicationVerificationFailure") {
                anyhow!(
                    "the server's certificate does not match your pinned fingerprint — \
                         someone may be impersonating {}, or the server was re-installed",
                    cfg.server
                )
            } else {
                anyhow!("TLS handshake with {} failed: {e}", cfg.server)
            }
        })?;
        let mut conn = Conn {
            framed: FramedConn::new(stream),
            events: VecDeque::new(),
            device: DeviceId([0; 16]),
            in_flight: false,
        };
        match conn.call(Request::Hello { version: PROTOCOL_VERSION, token }).await? {
            Response::Hello { device, .. } => conn.device = device,
            other => return Err(anyhow!("unexpected hello response: {other:?}")),
        }
        Ok(conn)
    }

    /// Send a request and wait for its response. Server-side errors become
    /// [`ServerError`]s. Events that arrive meanwhile are queued.
    pub async fn call(&mut self, req: Request) -> anyhow::Result<Response> {
        if self.in_flight {
            return Err(anyhow!("connection out of sync after a cancelled request"));
        }
        let name = request_name(&req);
        let started = std::time::Instant::now();
        self.in_flight = true;
        self.framed.send(&req).await?;
        // The longest legitimate wait is a mailbox long-poll (25 s on the
        // server); anything beyond this is a stalled connection, which must
        // surface as an error rather than hang the command.
        let result = tokio::time::timeout(CALL_TIMEOUT, async {
            loop {
                let frame = self.framed.recv::<ServerFrame>().await?;
                match frame {
                    ServerFrame::Event(Event::Envelope(e)) => self.events.push_back(e),
                    ServerFrame::Response(r) => return Ok::<_, anyhow::Error>(r),
                }
            }
        })
        .await;
        tracing::debug!(
            request = name,
            ms = started.elapsed().as_millis() as u64,
            ok = result.as_ref().map(|r| r.is_ok()).unwrap_or(false),
            "call"
        );
        match result {
            Err(_) => Err(anyhow!("no reply from the server to {name} within {}s", CALL_TIMEOUT.as_secs())),
            Ok(Err(e)) => Err(e),
            Ok(Ok(r)) => {
                self.in_flight = false;
                match r {
                    Response::Error { code, message } => Err(ServerError { code, message }.into()),
                    r => Ok(r),
                }
            }
        }
    }

    /// True if a request was cancelled before its response arrived.
    pub fn is_poisoned(&self) -> bool {
        self.in_flight
    }

    /// Wait for the next pushed envelope (after `Subscribe`).
    pub async fn next_event(&mut self) -> anyhow::Result<Envelope> {
        if let Some(e) = self.events.pop_front() {
            return Ok(e);
        }
        loop {
            match self.framed.recv::<ServerFrame>().await? {
                ServerFrame::Event(Event::Envelope(e)) => return Ok(e),
                ServerFrame::Response(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_host;

    #[test]
    fn hosts() {
        assert_eq!(split_host("yo.example.com:9000"), ("yo.example.com".into(), 9000));
        assert_eq!(split_host("yo.example.com"), ("yo.example.com".into(), 7443));
        assert_eq!(split_host("[::1]:8000"), ("::1".into(), 8000));
        assert_eq!(split_host("10.0.0.2:7443"), ("10.0.0.2".into(), 7443));
    }
}
