//! `server.toml`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    /// Any device may register.
    Open,
    /// New devices need a token created with `yo-server token create`.
    Token,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    pub listen: String,
    /// Host name (or IP) clients use to reach this server. Only used to
    /// print the `yo init` command.
    pub public_host: String,
    /// Certificate chain (PEM). Relative paths are relative to the data dir.
    pub cert: PathBuf,
    /// Private key (PEM).
    pub key: PathBuf,
    /// `true` when `cert` is a self-signed certificate that clients pin.
    /// `false` for a CA-issued certificate (e.g. Let's Encrypt).
    #[serde(default = "yes")]
    pub pinned: bool,
    pub registration: Registration,
    /// Undelivered envelopes are deleted after this many days.
    #[serde(default = "thirty")]
    pub message_ttl_days: u64,
    /// Max devices per inbox (i.e. per person per relationship).
    #[serde(default = "sixteen")]
    pub max_devices: usize,
}

fn yes() -> bool {
    true
}
fn thirty() -> u64 {
    30
}
fn sixteen() -> usize {
    16
}

impl Config {
    pub fn new(public_host: String, port: u16) -> Config {
        Config {
            listen: format!("0.0.0.0:{port}"),
            public_host,
            cert: "server.crt".into(),
            key: "server.key".into(),
            pinned: true,
            registration: Registration::Token,
            message_ttl_days: 30,
            max_devices: 16,
        }
    }

    pub fn load(dir: &Path) -> anyhow::Result<Config> {
        let path = dir.join("server.toml");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e} (did you run `yo-server init`?)", path.display()))?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        let body = toml::to_string_pretty(self)?;
        let text = format!(
            "# yo-server configuration. See docs/src/server/setup.md for every option.\n{body}"
        );
        std::fs::write(dir.join("server.toml"), text)?;
        Ok(())
    }

    pub fn resolve(&self, dir: &Path, p: &Path) -> PathBuf {
        if p.is_absolute() { p.to_path_buf() } else { dir.join(p) }
    }

    pub fn port(&self) -> u16 {
        self.listen.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(yo_proto::DEFAULT_PORT)
    }
}
