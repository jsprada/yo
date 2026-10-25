//! The passphrase agent, served by `yo daemon` over a local socket
//! (a Unix domain socket in the data directory, or a named pipe on Windows).
//!
//! While unlocked it holds the data key (DK) in memory so commands don't ask
//! for the passphrase every time. The key expires after a period without
//! use and is wiped on `yo lock`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use interprocess::local_socket::tokio::Stream;
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{ListenerOptions, Name};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use yo_crypto::{Key32, Zeroizing};
use yo_proto::frame::FramedConn;
use yo_store::Paths;

#[derive(Serialize, Deserialize)]
pub enum AgentReq {
    Unlock { dk: [u8; 32], minutes: u64 },
    Get,
    Lock,
    Status,
    Shutdown,
}

#[derive(Serialize, Deserialize)]
pub enum AgentResp {
    Ok,
    Key(Option<[u8; 32]>),
    Status(AgentStatus),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AgentStatus {
    pub pid: u32,
    /// Seconds until the cached key expires, if unlocked.
    pub unlocked_for: Option<u64>,
    /// Whether the daemon currently holds a connection to the server.
    pub connected: bool,
    pub last_error: Option<String>,
}

#[derive(Default)]
pub struct AgentState {
    key: Option<(Key32, Instant, Duration)>,
    pub connected: bool,
    pub last_error: Option<String>,
}

impl AgentState {
    fn key(&mut self) -> Option<[u8; 32]> {
        match &mut self.key {
            Some((k, expires, ttl)) if Instant::now() < *expires => {
                *expires = Instant::now() + *ttl; // sliding expiry
                Some(**k)
            }
            _ => {
                self.key = None;
                None
            }
        }
    }
}

fn name(paths: &Paths) -> std::io::Result<Name<'static>> {
    #[cfg(windows)]
    {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};
        paths.agent_pipe_name().to_ns_name::<GenericNamespaced>().map(|n| n.into_owned())
    }
    #[cfg(not(windows))]
    {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        let path = paths.agent_socket();
        if path.as_os_str().len() > 100 {
            return Err(std::io::Error::other(format!(
                "agent socket path is too long for this OS ({}); use a shorter YO_HOME",
                path.display()
            )));
        }
        path.to_fs_name::<GenericFilePath>().map(|n| n.into_owned())
    }
}

// ── client side ──────────────────────────────────────────────────────────

pub async fn request(paths: &Paths, req: AgentReq) -> std::io::Result<AgentResp> {
    let fut = async {
        let stream = Stream::connect(name(paths)?).await?;
        let mut conn = FramedConn::new(stream);
        conn.send(&req).await.map_err(std::io::Error::other)?;
        conn.recv::<AgentResp>().await.map_err(std::io::Error::other)
    };
    tokio::time::timeout(Duration::from_secs(3), fut)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "agent did not answer"))?
}

/// The cached data key, if the daemon is running and unlocked.
pub async fn get_key(paths: &Paths) -> Option<Key32> {
    match request(paths, AgentReq::Get).await {
        Ok(AgentResp::Key(Some(k))) => Some(Zeroizing::new(k)),
        _ => None,
    }
}

pub async fn unlock(paths: &Paths, dk: &Key32, minutes: u64) -> std::io::Result<()> {
    request(paths, AgentReq::Unlock { dk: **dk, minutes }).await.map(|_| ())
}

pub async fn status(paths: &Paths) -> Option<AgentStatus> {
    match request(paths, AgentReq::Status).await {
        Ok(AgentResp::Status(s)) => Some(s),
        _ => None,
    }
}

// ── server side (inside `yo daemon`) ─────────────────────────────────────

#[cfg(unix)]
fn same_user(paths: &Paths, stream: &Stream) -> bool {
    use interprocess::local_socket::traits::StreamCommon;
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(&paths.data_dir) else { return false };
    match stream.peer_creds() {
        Ok(c) => c.euid().is_none_or(|uid| uid == meta.uid()),
        Err(_) => true, // platform without peer credentials; directory permissions still apply
    }
}

#[cfg(not(unix))]
fn same_user(_paths: &Paths, _stream: &Stream) -> bool {
    true
}

pub async fn serve(paths: Paths, state: Arc<Mutex<AgentState>>, shutdown: Arc<Notify>) -> std::io::Result<()> {
    let listener = ListenerOptions::new().name(name(&paths)?).reclaim_name(true).try_overwrite(true).create_tokio()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(paths.agent_socket(), std::fs::Permissions::from_mode(0o600));
    }
    loop {
        let stream = listener.accept().await?;
        if !same_user(&paths, &stream) {
            continue;
        }
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut conn = FramedConn::new(stream);
            let Ok(req) = conn.recv::<AgentReq>().await else { return };
            let resp = {
                let mut s = state.lock().expect("agent state");
                match req {
                    AgentReq::Unlock { dk, minutes } => {
                        let ttl = Duration::from_secs(minutes.max(1) * 60);
                        s.key = Some((Zeroizing::new(dk), Instant::now() + ttl, ttl));
                        AgentResp::Ok
                    }
                    AgentReq::Get => AgentResp::Key(s.key()),
                    AgentReq::Lock => {
                        s.key = None; // Zeroizing wipes the key
                        AgentResp::Ok
                    }
                    AgentReq::Status => {
                        let unlocked_for = s
                            .key
                            .as_ref()
                            .and_then(|(_, exp, _)| exp.checked_duration_since(Instant::now()))
                            .map(|d| d.as_secs());
                        AgentResp::Status(AgentStatus {
                            pid: std::process::id(),
                            unlocked_for,
                            connected: s.connected,
                            last_error: s.last_error.clone(),
                        })
                    }
                    AgentReq::Shutdown => {
                        s.key = None;
                        shutdown.notify_waiters();
                        AgentResp::Ok
                    }
                }
            };
            let _ = conn.send(&resp).await;
        });
    }
}
