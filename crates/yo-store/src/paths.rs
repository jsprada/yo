//! Where yo! keeps its files.
//!
//! With `YO_HOME` set, everything lives in that one directory (handy for
//! tests and for running several identities on one machine). Otherwise the
//! OS conventions apply:
//!
//! | | Linux | macOS | Windows |
//! |---|---|---|---|
//! | config | `~/.config/yo` | `~/Library/Application Support/yo` | `%APPDATA%\yo\config` |
//! | data | `~/.local/share/yo` | `~/Library/Application Support/yo` | `%APPDATA%\yo\data` |
//! | state | `~/.local/state/yo` | (data dir) | (data dir) |

use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    pub fn at(home: impl AsRef<Path>) -> Paths {
        let h = home.as_ref().to_path_buf();
        Paths { config_dir: h.clone(), data_dir: h.clone(), state_dir: h }
    }

    pub fn from_env() -> Paths {
        if let Some(home) = std::env::var_os("YO_HOME") {
            return Paths::at(PathBuf::from(home));
        }
        match directories::ProjectDirs::from("", "", "yo") {
            Some(d) => Paths {
                config_dir: d.config_dir().to_path_buf(),
                data_dir: d.data_dir().to_path_buf(),
                state_dir: d.state_dir().unwrap_or(d.data_local_dir()).to_path_buf(),
            },
            None => Paths::at(".yo"),
        }
    }

    pub fn create_dirs(&self) -> std::io::Result<()> {
        for d in [&self.config_dir, &self.data_dir, &self.state_dir, &self.spool()] {
            std::fs::create_dir_all(d)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }

    pub fn config(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn keyfile(&self) -> PathBuf {
        self.data_dir.join("keyfile")
    }
    pub fn db(&self) -> PathBuf {
        self.data_dir.join("yo.db")
    }
    pub fn tls_cert(&self) -> PathBuf {
        self.data_dir.join("device.crt")
    }
    pub fn tls_key(&self) -> PathBuf {
        self.data_dir.join("device.key")
    }
    pub fn spool(&self) -> PathBuf {
        self.data_dir.join("spool")
    }
    pub fn lock(&self) -> PathBuf {
        self.data_dir.join("yo.lock")
    }
    /// Total unread count, read by the shell prompt snippet.
    pub fn unread(&self) -> PathBuf {
        self.state_dir.join("unread")
    }
    /// Unread messages already decrypted into the database.
    pub fn unread_db(&self) -> PathBuf {
        self.state_dir.join("unread.db")
    }
    pub fn daemon_pid(&self) -> PathBuf {
        self.state_dir.join("daemon.pid")
    }
    pub fn daemon_log(&self) -> PathBuf {
        self.state_dir.join("daemon.log")
    }
    /// Unix socket path for the agent (Unix only; Windows uses a named pipe).
    pub fn agent_socket(&self) -> PathBuf {
        self.data_dir.join("agent.sock")
    }
    /// Stable per-home name for the Windows named pipe.
    pub fn agent_pipe_name(&self) -> String {
        let h = yo_crypto::kdf::hmac(b"yo-agent-pipe", self.data_dir.to_string_lossy().as_bytes());
        format!("yo-agent-{}", &yo_proto::b32(&h)[..16])
    }
}
