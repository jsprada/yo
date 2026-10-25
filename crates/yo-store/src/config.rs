//! `config.toml` — non-secret client settings.

use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::{Result, StoreError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    /// `host:port` of the yo! server.
    pub server: String,
    /// `sha256:<base32>` pin of the server certificate. Absent when the
    /// server uses a CA-issued certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Extra pins accepted during certificate rotation. Add the new pin here,
    /// move everyone over, then make it the primary `pin` and drop the old.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_pins: Vec<String>,
    /// How long `yo unlock` (and a passphrase typed at a prompt) keeps the
    /// store unlocked in the agent, in minutes. 0 disables caching.
    #[serde(default = "default_ttl")]
    pub unlock_minutes: u64,
    /// Show the `yo!` banner on `yo` with no arguments.
    #[serde(default = "yes")]
    pub banner: bool,
}

fn default_ttl() -> u64 {
    15
}
fn yes() -> bool {
    true
}

impl ClientConfig {
    /// All accepted pins (primary first). Empty when the server uses web PKI.
    pub fn all_pins(&self) -> Vec<&str> {
        self.pin.iter().chain(self.extra_pins.iter()).map(|s| s.as_str()).collect()
    }

    pub fn load(paths: &Paths) -> Result<ClientConfig> {
        let text = std::fs::read_to_string(paths.config()).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StoreError::NotInitialized,
            _ => e.into(),
        })?;
        toml::from_str(&text).map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        let body = toml::to_string_pretty(self).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let text = format!("# yo! client settings — see `yo help` and the docs.\n{body}");
        crate::write_private(&paths.config(), text.as_bytes())?;
        Ok(())
    }
}
