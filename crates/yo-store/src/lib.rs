//! Local, encrypted client storage.
//!
//! Key hierarchy:
//!
//! ```text
//! passphrase ──Argon2id──▶ KEK ──wraps──▶ DK (data key, in `keyfile`)
//! DK  ──seals──▶ relationship bundle (nickname, RIK, RSK, pinned peer key…)
//! RSK ──seals──▶ that relationship's Olm state and every message row
//! ```
//!
//! Every RSK exists only inside its relationship's bundle, so deleting the
//! bundle row crypto-shreds the whole conversation (`yo burn`).

pub mod config;
pub mod keyfile;
pub mod model;
pub mod paths;
pub mod spool;
pub mod store;

pub use config::ClientConfig;
pub use keyfile::KeyFile;
pub use model::{Bundle, Direction, MessageKind, RelKind, StoredMessage};
pub use paths::Paths;
pub use store::{MessageRow, Relationship, Store};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("yo! is not set up here yet — run `yo init`")]
    NotInitialized,
    #[error("database: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] yo_crypto::CryptoError),
    #[error("corrupt data: {0}")]
    Corrupt(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Write a file readable only by the current user (0600 on Unix), atomically.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
