//! The spool: envelopes fetched from the server but not yet decrypted.
//!
//! The background daemon writes here without knowing the passphrase. The
//! envelopes are still end-to-end encrypted, so the spool is safe at rest.
//! `yo read` (or any unlocked command) drains it into the database.

use std::collections::HashSet;
use std::path::PathBuf;

use yo_proto::InboxId;
use yo_proto::msg::Envelope;

use crate::paths::Paths;

/// File name encodes the envelope id and whether it came from one of my own
/// devices (`m`) or from someone else (`o`), so the unread counter can be
/// computed without opening anything.
fn name(env: &Envelope) -> String {
    format!("{:016}.{}.env", env.id, if env.from_member { 'm' } else { 'o' })
}

pub fn write(paths: &Paths, env: &Envelope) -> std::io::Result<()> {
    let path = paths.spool().join(name(env));
    if path.exists() {
        return Ok(());
    }
    let bytes = postcard::to_stdvec(env).map_err(std::io::Error::other)?;
    crate::write_private(&path, &bytes)
}

/// All spooled envelopes in delivery order.
pub fn list(paths: &Paths) -> std::io::Result<Vec<(PathBuf, Envelope)>> {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(paths.spool()) {
        Ok(rd) => {
            rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "env")).collect()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(e),
    };
    files.sort();
    let mut out = Vec::new();
    for p in files {
        match std::fs::read(&p).ok().and_then(|b| postcard::from_bytes(&b).ok()) {
            Some(env) => out.push((p, env)),
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    Ok(out)
}

/// Record which inboxes belong to this device (see `Paths::inbox_index`).
pub fn write_inbox_index(paths: &Paths, inboxes: &[InboxId]) -> std::io::Result<()> {
    let text: String = inboxes.iter().map(|i| format!("{i}\n")).collect();
    crate::write_private(&paths.inbox_index(), text.as_bytes())
}

/// `None` when no index has been written yet (then every envelope counts).
pub fn read_inbox_index(paths: &Paths) -> Option<HashSet<InboxId>> {
    let text = std::fs::read_to_string(paths.inbox_index()).ok()?;
    Some(text.lines().filter_map(|l| l.trim().parse().ok()).collect())
}

/// Spooled envelopes that came from other people, for inboxes this device
/// actually has (junk for unknown inboxes is not counted; SECURITY_REVIEW.md L-6).
pub fn incoming_count(paths: &Paths) -> u64 {
    let known = read_inbox_index(paths);
    list(paths)
        .map(|envs| {
            envs.iter().filter(|(_, e)| !e.from_member && known.as_ref().is_none_or(|k| k.contains(&e.inbox))).count()
                as u64
        })
        .unwrap_or(0)
}

/// Recompute the unread counter the prompt reads. Pass `Some(n)` when the
/// number of unread messages in the database is known (store unlocked).
pub fn refresh_unread(paths: &Paths, db_unread: Option<u64>) -> std::io::Result<u64> {
    if let Some(n) = db_unread {
        crate::write_private(&paths.unread_db(), n.to_string().as_bytes())?;
    }
    let db = std::fs::read_to_string(paths.unread_db()).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    let total = db + incoming_count(paths);
    crate::write_private(&paths.unread(), total.to_string().as_bytes())?;
    Ok(total)
}

pub fn read_unread(paths: &Paths) -> u64 {
    std::fs::read_to_string(paths.unread()).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}
