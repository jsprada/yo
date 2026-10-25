//! The encrypted SQLite database (`yo.db`).
//!
//! Columns that are *not* encrypted: row ids, the relationship id a message
//! belongs to, a read flag, and an HMAC tag (keyed by DK) used to detect
//! duplicate deliveries. Names, bodies, timestamps and keys are only ever
//! stored sealed with XChaCha20-Poly1305, with the row id bound in as
//! associated data so rows cannot be swapped.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, params};
use yo_crypto::olm::OlmState;
use yo_crypto::{Key32, aead, kdf};

use crate::model::{Bundle, StoredMessage};
use crate::paths::Paths;
use crate::{Result, StoreError};

const SCHEMA: &str = r#"
PRAGMA journal_mode = DELETE;
PRAGMA secure_delete = ON;
CREATE TABLE IF NOT EXISTS canary (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    blob BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle BLOB NOT NULL,
    olm BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rel_id INTEGER NOT NULL,
    tag BLOB NOT NULL UNIQUE,
    read INTEGER NOT NULL,
    blob BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_rel ON messages(rel_id, id);
"#;

pub struct Relationship {
    pub id: i64,
    pub bundle: Bundle,
}

pub struct MessageRow {
    pub id: i64,
    pub rel_id: i64,
    pub read: bool,
    pub msg: StoredMessage,
}

pub struct Store {
    conn: Connection,
    dk: Key32,
}

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(what.to_string())
}

impl Store {
    pub fn open(paths: &Paths, dk: Key32) -> Result<Store> {
        let conn = Connection::open(paths.db())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(paths.db(), std::fs::Permissions::from_mode(0o600))?;
        }
        Self::with_conn(conn, dk)
    }

    pub fn open_in_memory(dk: Key32) -> Result<Store> {
        Self::with_conn(Connection::open_in_memory()?, dk)
    }

    fn with_conn(conn: Connection, dk: Key32) -> Result<Store> {
        conn.execute_batch(SCHEMA)?;
        let canary: Option<Vec<u8>> = conn.query_row("SELECT blob FROM canary", [], |r| r.get(0)).optional()?;
        match canary {
            Some(c) => {
                aead::open(&dk, b"yo/canary", &c).map_err(|_| StoreError::WrongPassphrase)?;
            }
            None => {
                conn.execute("INSERT INTO canary (id, blob) VALUES (1, ?1)", [aead::seal(&dk, b"yo/canary", b"yo!")])?;
            }
        }
        Ok(Store { conn, dk })
    }

    pub fn dk(&self) -> &Key32 {
        &self.dk
    }

    // ── relationships ────────────────────────────────────────────────────

    fn seal_bundle(&self, id: i64, b: &Bundle) -> Vec<u8> {
        let pt = yo_crypto::Zeroizing::new(serde_json::to_vec(b).expect("serializable"));
        aead::seal(&self.dk, format!("rel:{id}").as_bytes(), &pt)
    }

    fn open_bundle(&self, id: i64, blob: &[u8]) -> Result<Bundle> {
        let pt = yo_crypto::Zeroizing::new(aead::open(&self.dk, format!("rel:{id}").as_bytes(), blob)?);
        serde_json::from_slice(&pt).map_err(|_| corrupt("relationship"))
    }

    pub fn relationships(&self) -> Result<Vec<Relationship>> {
        let mut st = self.conn.prepare("SELECT id, bundle FROM relationships ORDER BY id")?;
        let rows: Vec<(i64, Vec<u8>)> =
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?;
        rows.into_iter().map(|(id, blob)| Ok(Relationship { id, bundle: self.open_bundle(id, &blob)? })).collect()
    }

    pub fn relationship(&self, id: i64) -> Result<Option<Relationship>> {
        let blob: Option<Vec<u8>> =
            self.conn.query_row("SELECT bundle FROM relationships WHERE id = ?1", [id], |r| r.get(0)).optional()?;
        blob.map(|b| Ok(Relationship { id, bundle: self.open_bundle(id, &b)? })).transpose()
    }

    pub fn insert_relationship(&mut self, bundle: Bundle, olm: &OlmState) -> Result<Relationship> {
        // Ids are never reused (AUTOINCREMENT); the row is created first so
        // its id can be bound into the ciphertext as associated data.
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO relationships (bundle, olm) VALUES (X'', X'')", [])?;
        let id = tx.last_insert_rowid();
        let rel = Relationship { id, bundle };
        let b = {
            let pt = yo_crypto::Zeroizing::new(serde_json::to_vec(&rel.bundle).expect("serializable"));
            aead::seal(&self.dk, format!("rel:{id}").as_bytes(), &pt)
        };
        let o = aead::seal(&rel.bundle.rsk, format!("olm:{id}").as_bytes(), &olm.to_bytes());
        tx.execute("UPDATE relationships SET bundle = ?2, olm = ?3 WHERE id = ?1", params![id, b, o])?;
        tx.commit()?;
        Ok(rel)
    }

    pub fn update_bundle(&self, rel: &Relationship) -> Result<()> {
        self.conn.execute(
            "UPDATE relationships SET bundle = ?2 WHERE id = ?1",
            params![rel.id, self.seal_bundle(rel.id, &rel.bundle)],
        )?;
        Ok(())
    }

    pub fn load_olm(&self, rel: &Relationship) -> Result<OlmState> {
        let blob: Vec<u8> =
            self.conn.query_row("SELECT olm FROM relationships WHERE id = ?1", [rel.id], |r| r.get(0))?;
        let pt = yo_crypto::Zeroizing::new(aead::open(&rel.bundle.rsk, format!("olm:{}", rel.id).as_bytes(), &blob)?);
        Ok(OlmState::from_bytes(&pt)?)
    }

    pub fn save_olm(&self, rel: &Relationship, olm: &OlmState) -> Result<()> {
        let o = aead::seal(&rel.bundle.rsk, format!("olm:{}", rel.id).as_bytes(), &olm.to_bytes());
        self.conn.execute("UPDATE relationships SET olm = ?2 WHERE id = ?1", params![rel.id, o])?;
        Ok(())
    }

    /// Crypto-shred a relationship: delete its bundle (the only copy of its
    /// RSK and RIK), its Olm state and all of its messages, then VACUUM so
    /// the freed pages are rewritten.
    pub fn shred_relationship(&mut self, id: i64) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM messages WHERE rel_id = ?1", [id])?;
        tx.execute("DELETE FROM relationships WHERE id = ?1", [id])?;
        tx.commit()?;
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }

    // ── messages ─────────────────────────────────────────────────────────

    fn tag(&self, rel_id: i64, uuid: &[u8; 16]) -> [u8; 32] {
        let mut data = format!("msg:{rel_id}:").into_bytes();
        data.extend_from_slice(uuid);
        kdf::hmac(self.dk.as_ref(), &data)
    }

    /// Store a message. Returns its local number, or `None` if this message
    /// (same relationship + uuid) was already stored.
    pub fn insert_message(&mut self, rel: &Relationship, msg: &StoredMessage, read: bool) -> Result<Option<i64>> {
        let tag = self.tag(rel.id, &msg.uuid);
        let tx = self.conn.transaction()?;
        let exists = tx.query_row("SELECT 1 FROM messages WHERE tag = ?1", [&tag[..]], |_| Ok(())).optional()?;
        if exists.is_some() {
            return Ok(None);
        }
        // Message numbers are what `yo reply N` uses, so they are never reused.
        tx.execute(
            "INSERT INTO messages (rel_id, tag, read, blob) VALUES (?1, ?2, ?3, X'')",
            params![rel.id, &tag[..], read],
        )?;
        let id = tx.last_insert_rowid();
        let pt = yo_crypto::Zeroizing::new(serde_json::to_vec(msg).expect("serializable"));
        let blob = aead::seal(&rel.bundle.rsk, format!("msg:{id}:{}", rel.id).as_bytes(), &pt);
        tx.execute("UPDATE messages SET blob = ?2 WHERE id = ?1", params![id, blob])?;
        tx.commit()?;
        Ok(Some(id))
    }

    pub fn find_by_uuid(&self, rel: &Relationship, uuid: &[u8; 16]) -> Result<Option<i64>> {
        let tag = self.tag(rel.id, uuid);
        Ok(self.conn.query_row("SELECT id FROM messages WHERE tag = ?1", [&tag[..]], |r| r.get(0)).optional()?)
    }

    fn decode(
        &self,
        rels: &HashMap<i64, &Relationship>,
        id: i64,
        rel_id: i64,
        read: bool,
        blob: &[u8],
    ) -> Result<MessageRow> {
        let rel = rels.get(&rel_id).ok_or_else(|| corrupt("message without relationship"))?;
        let pt = yo_crypto::Zeroizing::new(aead::open(&rel.bundle.rsk, format!("msg:{id}:{rel_id}").as_bytes(), blob)?);
        let msg = serde_json::from_slice(&pt).map_err(|_| corrupt("message"))?;
        Ok(MessageRow { id, rel_id, read, msg })
    }

    fn query_messages(&self, rels: &[Relationship], sql: &str, args: impl rusqlite::Params) -> Result<Vec<MessageRow>> {
        let map: HashMap<i64, &Relationship> = rels.iter().map(|r| (r.id, r)).collect();
        let mut st = self.conn.prepare(sql)?;
        let rows: Vec<(i64, i64, bool, Vec<u8>)> = st
            .query_map(args, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<std::result::Result<_, _>>()?;
        rows.into_iter().map(|(id, rel, read, blob)| self.decode(&map, id, rel, read, &blob)).collect()
    }

    pub fn message(&self, rels: &[Relationship], id: i64) -> Result<Option<MessageRow>> {
        Ok(self.query_messages(rels, "SELECT id, rel_id, read, blob FROM messages WHERE id = ?1", [id])?.pop())
    }

    /// The last `limit` messages of a relationship, oldest first.
    pub fn history(&self, rel: &Relationship, limit: usize) -> Result<Vec<MessageRow>> {
        let mut v = self.query_messages(
            std::slice::from_ref(rel),
            "SELECT id, rel_id, read, blob FROM messages WHERE rel_id = ?1 ORDER BY id DESC LIMIT ?2",
            params![rel.id, limit as i64],
        )?;
        v.reverse();
        Ok(v)
    }

    pub fn unread(&self, rels: &[Relationship]) -> Result<Vec<MessageRow>> {
        self.query_messages(rels, "SELECT id, rel_id, read, blob FROM messages WHERE read = 0 ORDER BY id", [])
    }

    pub fn mark_read(&mut self, ids: &[i64]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for id in ids {
            tx.execute("UPDATE messages SET read = 1 WHERE id = ?1", [id])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn unread_count(&self) -> Result<u64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM messages WHERE read = 0", [], |r| r.get::<_, i64>(0))? as u64)
    }

    pub fn unread_by_rel(&self) -> Result<HashMap<i64, u64>> {
        let mut st = self.conn.prepare("SELECT rel_id, COUNT(*) FROM messages WHERE read = 0 GROUP BY rel_id")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Direction, MessageKind, RelKind};
    use yo_crypto::rik::Rik;

    fn bundle(name: &str) -> Bundle {
        Bundle {
            kind: RelKind::Contact,
            nickname: name.into(),
            rik_secret: *Rik::generate().secret(),
            rsk: yo_crypto::random(),
            peer_rik: Some(Rik::generate().public()),
            verified: true,
            created_at: 1,
            my_list_version: 0,
            peer_list_version: 0,
            my_devices: vec![],
            peer_devices: vec![],
        }
    }

    fn msg(body: &str, uuid: u8) -> StoredMessage {
        StoredMessage {
            uuid: [uuid; 16],
            direction: Direction::In,
            kind: MessageKind::Text,
            sent_at: 1_700_000_000,
            received_at: 1_700_000_001,
            body: body.into(),
            reply_to: None,
        }
    }

    #[test]
    fn messages_are_encrypted_and_shredded() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let dk = yo_crypto::random_key();
        let mut s = Store::open(&paths, dk.clone()).unwrap();
        let alice = s.insert_relationship(bundle("alice"), &OlmState::new()).unwrap();
        let carol = s.insert_relationship(bundle("carol"), &OlmState::new()).unwrap();
        let n = s.insert_message(&alice, &msg("meet at the zebra crossing", 1), false).unwrap().unwrap();
        assert!(s.insert_message(&alice, &msg("dup", 1), false).unwrap().is_none(), "dedupe by uuid");
        s.insert_message(&carol, &msg("carol says hi", 2), false).unwrap();

        let rels = s.relationships().unwrap();
        assert_eq!(rels.len(), 2);
        assert_eq!(s.message(&rels, n).unwrap().unwrap().msg.body, "meet at the zebra crossing");
        assert_eq!(s.unread_count().unwrap(), 2);
        s.load_olm(&rels[0]).unwrap();

        // Nothing readable on disk.
        drop(s);
        let raw = std::fs::read(paths.db()).unwrap();
        for needle in ["zebra", "alice", "carol says"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()), "{needle} leaked");
        }

        // Wrong key is rejected.
        assert!(matches!(Store::open(&paths, yo_crypto::random_key()), Err(StoreError::WrongPassphrase)));

        // Shredding alice keeps carol intact.
        let mut s = Store::open(&paths, dk).unwrap();
        s.shred_relationship(alice.id).unwrap();
        let rels = s.relationships().unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].bundle.nickname, "carol");
        assert!(s.message(&rels, n).unwrap().is_none());
        assert_eq!(s.unread(&rels).unwrap()[0].msg.body, "carol says hi");

        // Message numbers are never reused after a shred.
        let carol = s.relationships().unwrap().pop().unwrap();
        let next = s.insert_message(&carol, &msg("later", 9), false).unwrap().unwrap();
        assert!(next > n + 1, "{next} reused an old number");
    }

    #[test]
    fn rows_cannot_be_swapped() {
        let mut s = Store::open_in_memory(yo_crypto::random_key()).unwrap();
        let a = s.insert_relationship(bundle("a"), &OlmState::new()).unwrap();
        let m1 = s.insert_message(&a, &msg("one", 1), false).unwrap().unwrap();
        let m2 = s.insert_message(&a, &msg("two", 2), false).unwrap().unwrap();
        // Copy row 1's ciphertext into row 2: must fail to decrypt.
        s.conn
            .execute("UPDATE messages SET blob = (SELECT blob FROM messages WHERE id = ?1) WHERE id = ?2", [m1, m2])
            .unwrap();
        let rels = s.relationships().unwrap();
        assert!(s.message(&rels, m2).is_err());
    }
}
