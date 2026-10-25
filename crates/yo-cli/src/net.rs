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

pub struct Conn {
    framed: FramedConn<TlsStream<TcpStream>>,
    events: VecDeque<Envelope>,
    pub device: DeviceId,
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
        let trust = match &cfg.pin {
            Some(p) => ServerTrust::Pinned(tls::parse_pin(p)?),
            None => ServerTrust::WebPki,
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
        let mut conn = Conn { framed: FramedConn::new(stream), events: VecDeque::new(), device: DeviceId([0; 16]) };
        match conn.call(Request::Hello { version: PROTOCOL_VERSION, token }).await? {
            Response::Hello { device, .. } => conn.device = device,
            other => return Err(anyhow!("unexpected hello response: {other:?}")),
        }
        Ok(conn)
    }

    /// Send a request and wait for its response. Server-side errors become
    /// [`ServerError`]s. Events that arrive meanwhile are queued.
    pub async fn call(&mut self, req: Request) -> anyhow::Result<Response> {
        self.framed.send(&req).await?;
        loop {
            match self.framed.recv::<ServerFrame>().await? {
                ServerFrame::Response(Response::Error { code, message }) => {
                    return Err(ServerError { code, message }.into());
                }
                ServerFrame::Response(r) => return Ok(r),
                ServerFrame::Event(Event::Envelope(e)) => self.events.push_back(e),
            }
        }
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

    /// Send a request without waiting for its response (the daemon uses this
    /// for acks and pings while it is waiting for events).
    pub async fn send_only(&mut self, req: Request) -> anyhow::Result<()> {
        self.framed.send(&req).await?;
        Ok(())
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
