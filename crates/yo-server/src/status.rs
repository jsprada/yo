//! Local status socket for a status page on the same machine.
//!
//! A Unix socket; every connection gets one JSON line and is closed. Nothing
//! is read, so there is no request surface. The socket is group-readable so
//! a separate, unprivileged status-page user in the `yo` group can poll it.

use std::path::Path;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tracing::{info, warn};
use yo_proto::{PROTOCOL_VERSION, now};

/// "0.1.0 (a2012fc)" when built by the deploy scripts, else "0.1.0".
pub fn version_string() -> String {
    let sha = env!("YO_BUILD_SHA");
    if sha.is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        format!("{} ({sha})", env!("CARGO_PKG_VERSION"))
    }
}

#[derive(Serialize)]
pub struct Status {
    pub service: &'static str,
    pub version: String,
    pub protocol: u16,
    pub started_at: u64,
    pub now: u64,
}

pub async fn serve(path: &Path, started_at: u64) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    info!("status socket at {}", path.display());
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("status socket accept: {e}");
                continue;
            }
        };
        let line = serde_json::to_string(&Status {
            service: "yo-server",
            version: version_string(),
            protocol: PROTOCOL_VERSION,
            started_at,
            now: now(),
        })
        .unwrap_or_default();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let _ = stream.write_all(line.as_bytes()).await;
                let _ = stream.write_all(b"\n").await;
                let _ = stream.shutdown().await;
            })
            .await;
        });
    }
}
