//! `yo-server`: a relay that stores and forwards end-to-end-encrypted
//! envelopes. It can authenticate devices (mTLS) but can never read messages.

pub mod cli;
pub mod config;
pub mod db;
pub mod mailbox;
pub mod server;

use std::path::Path;
use std::sync::Arc;

pub use config::{Config, Registration};
pub use server::Server;

/// Build the rustls server config from the files named in `cfg`.
pub fn tls_config(dir: &Path, cfg: &Config) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let chain = yo_proto::tls::load_chain_file(&cfg.resolve(dir, &cfg.cert))?;
    let key = yo_proto::tls::load_key_file(&cfg.resolve(dir, &cfg.key))?;
    Ok(Arc::new(yo_proto::tls::server_config(chain, key)?))
}

/// The pin clients should use, or `None` for CA-issued certificates.
pub fn pin(dir: &Path, cfg: &Config) -> anyhow::Result<Option<String>> {
    if !cfg.pinned {
        return Ok(None);
    }
    let chain = yo_proto::tls::load_chain_file(&cfg.resolve(dir, &cfg.cert))?;
    Ok(Some(yo_proto::tls::format_pin(&yo_proto::tls::spki_hash(&chain[0])?)))
}
