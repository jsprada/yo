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

/// Abuse limits. Every value has a default that suits a small server; raise
/// them for big deployments, lower them if the server is being abused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Concurrent connections accepted from one IP address (checked before
    /// the TLS handshake).
    pub connections_per_ip: u32,
    /// New connections per minute from one IP address (token bucket; the
    /// burst size is the same number).
    pub new_connections_per_minute_per_ip: u32,
    /// Concurrent connections per registered device.
    pub connections_per_device: u32,
    /// Ciphertext queued for one device, in MiB. Senders get `RateLimited`
    /// when a recipient's queue is full.
    pub queue_mib_per_device: u64,
    /// Ciphertext one device may send per hour, in MiB.
    pub send_mib_per_hour_per_device: u64,
    /// `Send` requests per minute per device.
    pub sends_per_minute: u32,
    /// Invite mailboxes that may exist at once, server-wide.
    pub mailboxes: usize,
    /// Failed registration attempts (bad or missing token) per minute from
    /// one IP address before further attempts are refused.
    pub failed_registrations_per_minute_per_ip: u32,
    /// SQLite connections in the pool.
    pub db_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connections_per_ip: 32,
            new_connections_per_minute_per_ip: 60,
            connections_per_device: 4,
            queue_mib_per_device: 64,
            send_mib_per_hour_per_device: 256,
            sends_per_minute: 120,
            mailboxes: 2000,
            failed_registrations_per_minute_per_ip: 5,
            db_connections: 4,
        }
    }
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
    #[serde(default)]
    pub limits: Limits,
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
            limits: Limits::default(),
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
        let text = format!("# yo-server configuration. See docs/src/server/setup.md for every option.\n{body}");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_config_without_limits_still_loads() {
        let text =
            "listen = \"0.0.0.0:7443\"\npublic_host = \"h\"\ncert = \"c\"\nkey = \"k\"\nregistration = \"token\"\n";
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.limits, Limits::default());
        let round: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(round.limits, Limits::default());
    }
}
