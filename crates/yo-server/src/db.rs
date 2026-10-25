//! Server storage (SQLite).
//!
//! The server stores only what it needs to route ciphertext:
//! inbox IDs with their signed device lists, one-time public keys, and
//! end-to-end-encrypted envelopes until the recipient acknowledges them.
//! It never stores names, contacts or plaintext.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use yo_proto::msg::{Envelope, SignedDeviceList, SignedPreKey};
use yo_proto::{DeviceId, InboxId};

pub struct Db {
    conn: Connection,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS registered (
    device BLOB PRIMARY KEY,
    registered_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    uses_left INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS inboxes (
    inbox BLOB PRIMARY KEY,
    version INTEGER NOT NULL,
    list BLOB,
    burned_at INTEGER
);
CREATE TABLE IF NOT EXISTS members (
    inbox BLOB NOT NULL,
    device BLOB NOT NULL,
    PRIMARY KEY (inbox, device)
);
CREATE INDEX IF NOT EXISTS members_device ON members(device);
CREATE TABLE IF NOT EXISTS prekeys (
    id INTEGER PRIMARY KEY,
    inbox BLOB NOT NULL,
    device BLOB NOT NULL,
    fallback INTEGER NOT NULL,
    key BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS prekeys_owner ON prekeys(inbox, device);
CREATE TABLE IF NOT EXISTS envelopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device BLOB NOT NULL,
    inbox BLOB NOT NULL,
    sender BLOB NOT NULL,
    from_member INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    blob BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS envelopes_device ON envelopes(device, id);
"#;

pub enum InboxState {
    Missing,
    Burned,
    Live { version: u64, list: SignedDeviceList },
}

fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
    postcard::to_stdvec(v).expect("serializable")
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn })
    }

    pub fn open_in_memory() -> rusqlite::Result<Db> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn })
    }

    // ── registration ──────────────────────────────────────────────────────

    pub fn is_registered(&self, device: &DeviceId) -> rusqlite::Result<bool> {
        self.conn
            .query_row("SELECT 1 FROM registered WHERE device = ?1", [&device.0[..]], |_| Ok(()))
            .optional()
            .map(|r| r.is_some())
    }

    pub fn register(&self, device: &DeviceId, now: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO registered (device, registered_at) VALUES (?1, ?2)",
            params![&device.0[..], now as i64],
        )?;
        Ok(())
    }

    /// Register `device` by consuming one use of `token`, atomically: if the
    /// registration can't be stored, the token is not consumed. Returns
    /// false (and changes nothing) when the token is invalid or used up.
    pub fn register_with_token(&mut self, device: &DeviceId, token: &str, now: u64) -> rusqlite::Result<bool> {
        let tx = self.conn.transaction()?;
        let n =
            tx.execute("UPDATE tokens SET uses_left = uses_left - 1 WHERE token = ?1 AND uses_left > 0", [token])?;
        if n != 1 {
            return Ok(false);
        }
        tx.execute(
            "INSERT OR IGNORE INTO registered (device, registered_at) VALUES (?1, ?2)",
            params![&device.0[..], now as i64],
        )?;
        tx.execute("DELETE FROM tokens WHERE uses_left <= 0", [])?;
        tx.commit()?;
        Ok(true)
    }

    pub fn create_token(&self, token: &str, uses: u32, note: &str, now: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO tokens (token, uses_left, created_at, note) VALUES (?1, ?2, ?3, ?4)",
            params![token, uses, now as i64, note],
        )?;
        Ok(())
    }

    pub fn list_tokens(&self) -> rusqlite::Result<Vec<(String, u32, u64, String)>> {
        let mut st = self.conn.prepare("SELECT token, uses_left, created_at, note FROM tokens ORDER BY created_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u64, r.get(3)?)))?;
        rows.collect()
    }

    pub fn revoke_token(&self, token: &str) -> rusqlite::Result<bool> {
        Ok(self.conn.execute("DELETE FROM tokens WHERE token = ?1", [token])? == 1)
    }

    // ── inboxes & device lists ───────────────────────────────────────────

    pub fn inbox(&self, inbox: &InboxId) -> rusqlite::Result<InboxState> {
        let row: Option<(i64, Option<Vec<u8>>, Option<i64>)> = self
            .conn
            .query_row("SELECT version, list, burned_at FROM inboxes WHERE inbox = ?1", [&inbox.0[..]], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        Ok(match row {
            None => InboxState::Missing,
            Some((_, _, Some(_))) => InboxState::Burned,
            Some((version, Some(list), None)) => match postcard::from_bytes(&list) {
                Ok(list) => InboxState::Live { version: version as u64, list },
                Err(_) => InboxState::Missing,
            },
            Some((_, None, None)) => InboxState::Missing,
        })
    }

    /// Store a new device list (already verified by the caller) and update
    /// membership. Removed devices lose their keys and queued envelopes.
    pub fn put_list(&mut self, signed: &SignedDeviceList) -> rusqlite::Result<()> {
        let inbox = &signed.list.inbox.0[..];
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO inboxes (inbox, version, list, burned_at) VALUES (?1, ?2, ?3, NULL)
             ON CONFLICT(inbox) DO UPDATE SET version = excluded.version, list = excluded.list",
            params![inbox, signed.list.version as i64, enc(signed)],
        )?;
        let old: Vec<Vec<u8>> = {
            let mut st = tx.prepare("SELECT device FROM members WHERE inbox = ?1")?;
            st.query_map([inbox], |r| r.get(0))?.collect::<Result<_, _>>()?
        };
        tx.execute("DELETE FROM members WHERE inbox = ?1", [inbox])?;
        for d in &signed.list.devices {
            tx.execute(
                "INSERT OR IGNORE INTO members (inbox, device) VALUES (?1, ?2)",
                params![inbox, &d.device.0[..]],
            )?;
        }
        for dev in old {
            if !signed.list.devices.iter().any(|d| d.device.0[..] == dev[..]) {
                tx.execute("DELETE FROM prekeys WHERE inbox = ?1 AND device = ?2", params![inbox, dev])?;
                tx.execute("DELETE FROM envelopes WHERE inbox = ?1 AND device = ?2", params![inbox, dev])?;
            }
        }
        tx.commit()
    }

    pub fn is_member(&self, inbox: &InboxId, device: &DeviceId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM members WHERE inbox = ?1 AND device = ?2",
                params![&inbox.0[..], &device.0[..]],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
    }

    /// Burn an inbox: forget its device list, members and keys, and keep a
    /// marker so new sends are refused. Already-queued envelopes stay
    /// deliverable (they carry the burn notice to offline devices).
    pub fn burn(&mut self, inbox: &InboxId, now: u64) -> rusqlite::Result<()> {
        let i = &inbox.0[..];
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO inboxes (inbox, version, list, burned_at) VALUES (?1, 0, NULL, ?2)
             ON CONFLICT(inbox) DO UPDATE SET list = NULL, burned_at = excluded.burned_at",
            params![i, now as i64],
        )?;
        tx.execute("DELETE FROM members WHERE inbox = ?1", [i])?;
        tx.execute("DELETE FROM prekeys WHERE inbox = ?1", [i])?;
        tx.commit()
    }

    // ── one-time keys ────────────────────────────────────────────────────

    pub fn publish_keys(
        &mut self,
        inbox: &InboxId,
        device: &DeviceId,
        one_time: &[SignedPreKey],
        fallback: Option<&SignedPreKey>,
        cap: usize,
    ) -> rusqlite::Result<()> {
        let (i, d) = (&inbox.0[..], &device.0[..]);
        let tx = self.conn.transaction()?;
        for k in one_time {
            tx.execute(
                "INSERT INTO prekeys (inbox, device, fallback, key) VALUES (?1, ?2, 0, ?3)",
                params![i, d, enc(k)],
            )?;
        }
        // Keep only the newest `cap` one-time keys.
        tx.execute(
            "DELETE FROM prekeys WHERE inbox = ?1 AND device = ?2 AND fallback = 0 AND id NOT IN
               (SELECT id FROM prekeys WHERE inbox = ?1 AND device = ?2 AND fallback = 0 ORDER BY id DESC LIMIT ?3)",
            params![i, d, cap as i64],
        )?;
        if let Some(f) = fallback {
            tx.execute("DELETE FROM prekeys WHERE inbox = ?1 AND device = ?2 AND fallback = 1", params![i, d])?;
            tx.execute(
                "INSERT INTO prekeys (inbox, device, fallback, key) VALUES (?1, ?2, 1, ?3)",
                params![i, d, enc(f)],
            )?;
        }
        tx.commit()
    }

    pub fn key_count(&self, inbox: &InboxId, device: &DeviceId) -> rusqlite::Result<u32> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM prekeys WHERE inbox = ?1 AND device = ?2 AND fallback = 0",
            params![&inbox.0[..], &device.0[..]],
            |r| r.get(0),
        )
    }

    /// Hand out (and delete) one one-time key, or the fallback key if none are left.
    pub fn claim_key(&mut self, inbox: &InboxId, device: &DeviceId) -> rusqlite::Result<Option<SignedPreKey>> {
        let (i, d) = (&inbox.0[..], &device.0[..]);
        let tx = self.conn.transaction()?;
        let row: Option<(i64, i64, Vec<u8>)> = tx
            .query_row(
                "SELECT id, fallback, key FROM prekeys WHERE inbox = ?1 AND device = ?2 ORDER BY fallback ASC, id ASC LIMIT 1",
                params![i, d],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let out = match row {
            None => None,
            Some((id, fallback, key)) => {
                if fallback == 0 {
                    tx.execute("DELETE FROM prekeys WHERE id = ?1", [id])?;
                }
                postcard::from_bytes(&key).ok()
            }
        };
        tx.commit()?;
        Ok(out)
    }

    // ── envelopes ────────────────────────────────────────────────────────

    pub fn insert_envelope(
        &self,
        device: &DeviceId,
        inbox: &InboxId,
        sender: &DeviceId,
        from_member: bool,
        ts: u64,
        blob: &[u8],
    ) -> rusqlite::Result<Envelope> {
        self.conn.execute(
            "INSERT INTO envelopes (device, inbox, sender, from_member, ts, blob) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![&device.0[..], &inbox.0[..], &sender.0[..], from_member, ts as i64, blob],
        )?;
        Ok(Envelope {
            id: self.conn.last_insert_rowid() as u64,
            inbox: *inbox,
            sender: *sender,
            from_member,
            ts,
            blob: blob.to_vec(),
        })
    }

    /// Up to `limit` queued envelopes, oldest first, stopping once `max_bytes`
    /// of ciphertext is reached (always at least one), so a response fits in
    /// a frame no matter how big the backlog is.
    pub fn fetch(&self, device: &DeviceId, limit: usize, max_bytes: usize) -> rusqlite::Result<Vec<Envelope>> {
        let mut st = self.conn.prepare(
            "SELECT id, inbox, sender, from_member, ts, blob FROM envelopes WHERE device = ?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = st.query_map(params![&device.0[..], limit as i64], |r| {
            let inbox: Vec<u8> = r.get(1)?;
            let sender: Vec<u8> = r.get(2)?;
            Ok(Envelope {
                id: r.get::<_, i64>(0)? as u64,
                inbox: InboxId(inbox.try_into().unwrap_or([0; 32])),
                sender: DeviceId(sender.try_into().unwrap_or([0; 16])),
                from_member: r.get(3)?,
                ts: r.get::<_, i64>(4)? as u64,
                blob: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let env = row?;
            if !out.is_empty() && bytes + env.blob.len() > max_bytes {
                break;
            }
            bytes += env.blob.len();
            out.push(env);
        }
        Ok(out)
    }

    /// Ciphertext currently queued for a device.
    pub fn queued_bytes(&self, device: &DeviceId) -> rusqlite::Result<u64> {
        self.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(blob)), 0) FROM envelopes WHERE device = ?1",
            [&device.0[..]],
            |r| r.get::<_, i64>(0).map(|n| n as u64),
        )
    }

    pub fn ack(&mut self, device: &DeviceId, ids: &[u64]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM envelopes WHERE device = ?1 AND id = ?2", params![&device.0[..], *id as i64])?;
        }
        tx.commit()
    }

    // ── housekeeping ─────────────────────────────────────────────────────

    pub fn expire(&self, envelopes_before: u64, burned_before: u64) -> rusqlite::Result<usize> {
        let a = self.conn.execute("DELETE FROM envelopes WHERE ts < ?1", [envelopes_before as i64])?;
        let b = self
            .conn
            .execute("DELETE FROM inboxes WHERE burned_at IS NOT NULL AND burned_at < ?1", [burned_before as i64])?;
        Ok(a + b)
    }

    pub fn stats(&self) -> rusqlite::Result<[(&'static str, i64); 5]> {
        let c = |sql: &str| self.conn.query_row(sql, [], |r| r.get::<_, i64>(0));
        Ok([
            ("registered devices", c("SELECT COUNT(*) FROM registered")?),
            ("live inboxes", c("SELECT COUNT(*) FROM inboxes WHERE burned_at IS NULL")?),
            ("burned inboxes (markers)", c("SELECT COUNT(*) FROM inboxes WHERE burned_at IS NOT NULL")?),
            ("queued envelopes", c("SELECT COUNT(*) FROM envelopes")?),
            ("one-time keys", c("SELECT COUNT(*) FROM prekeys")?),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_registration_is_atomic_and_single_use() {
        let mut db = Db::open_in_memory().unwrap();
        let a = DeviceId([1; 16]);
        let b = DeviceId([2; 16]);
        db.create_token("t1", 1, "", 0).unwrap();
        assert!(!db.register_with_token(&a, "nope", 1).unwrap(), "bad token changes nothing");
        assert!(!db.is_registered(&a).unwrap());
        assert_eq!(db.list_tokens().unwrap().len(), 1, "token untouched after a bad attempt");
        assert!(db.register_with_token(&a, "t1", 1).unwrap());
        assert!(db.is_registered(&a).unwrap());
        assert!(db.list_tokens().unwrap().is_empty(), "used-up token is deleted");
        assert!(!db.register_with_token(&b, "t1", 2).unwrap());
        assert!(!db.is_registered(&b).unwrap());
    }
}
