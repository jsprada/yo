//! In-memory relay mailboxes for the invite / link key exchange.
//!
//! Mailboxes only ever hold SPAKE2 messages and PAKE-encrypted payloads, live
//! for at most ten minutes, accept a single joiner, and are never written to
//! disk.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use yo_proto::msg::Side;

pub const MAILBOX_TTL: Duration = Duration::from_secs(600);
const MAX_MESSAGES_PER_SIDE: usize = 8;
const MAX_MESSAGE: usize = 64 * 1024;

struct Mailbox {
    created: Instant,
    joined: bool,
    opener: Vec<Vec<u8>>,
    joiner: Vec<Vec<u8>>,
    notify: Arc<Notify>,
}

impl Mailbox {
    fn side(&mut self, s: Side) -> &mut Vec<Vec<u8>> {
        match s {
            Side::Opener => &mut self.opener,
            Side::Joiner => &mut self.joiner,
        }
    }
}

#[derive(Default)]
pub struct Mailboxes {
    boxes: HashMap<u32, Mailbox>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MailboxError {
    NotFound,
    AlreadyJoined,
    TooLarge,
}

impl Mailboxes {
    pub fn open(&mut self) -> u32 {
        self.expire();
        // Short numbers while the server is quiet, longer ones if busy.
        let mut range = 1000u32;
        loop {
            for _ in 0..32 {
                let n = 1 + getrandom::u32().expect("os rng") % (range - 1);
                if !self.boxes.contains_key(&n) {
                    self.boxes.insert(
                        n,
                        Mailbox {
                            created: Instant::now(),
                            joined: false,
                            opener: vec![],
                            joiner: vec![],
                            notify: Arc::new(Notify::new()),
                        },
                    );
                    return n;
                }
            }
            range = range.saturating_mul(10);
        }
    }

    pub fn join(&mut self, n: u32) -> Result<(), MailboxError> {
        let m = self.boxes.get_mut(&n).ok_or(MailboxError::NotFound)?;
        if m.joined {
            // One attempt only: a second joiner means someone guessed.
            self.close(n);
            return Err(MailboxError::AlreadyJoined);
        }
        m.joined = true;
        Ok(())
    }

    pub fn put(&mut self, n: u32, side: Side, msg: Vec<u8>) -> Result<(), MailboxError> {
        if msg.len() > MAX_MESSAGE {
            return Err(MailboxError::TooLarge);
        }
        let m = self.boxes.get_mut(&n).ok_or(MailboxError::NotFound)?;
        let q = m.side(side);
        if q.len() >= MAX_MESSAGES_PER_SIDE {
            return Err(MailboxError::TooLarge);
        }
        q.push(msg);
        m.notify.notify_waiters();
        Ok(())
    }

    /// Message `index` from the side opposite `side`, plus a handle to wait
    /// on when it is not there yet.
    pub fn get(&mut self, n: u32, side: Side, index: u32) -> Result<(Option<Vec<u8>>, Arc<Notify>), MailboxError> {
        let m = self.boxes.get_mut(&n).ok_or(MailboxError::NotFound)?;
        let notify = m.notify.clone();
        let msg = m.side(side.other()).get(index as usize).cloned();
        Ok((msg, notify))
    }

    pub fn close(&mut self, n: u32) {
        if let Some(m) = self.boxes.remove(&n) {
            m.notify.notify_waiters();
        }
    }

    pub fn expire(&mut self) {
        let dead: Vec<u32> = self
            .boxes
            .iter()
            .filter(|(_, m)| m.created.elapsed() > MAILBOX_TTL)
            .map(|(n, _)| *n)
            .collect();
        for n in dead {
            self.close(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_joiner_and_messages() {
        let mut mb = Mailboxes::default();
        let n = mb.open();
        mb.put(n, Side::Opener, b"a0".to_vec()).unwrap();
        mb.join(n).unwrap();
        assert_eq!(mb.get(n, Side::Joiner, 0).unwrap().0.unwrap(), b"a0");
        assert!(mb.get(n, Side::Opener, 0).unwrap().0.is_none());
        // A second join burns the mailbox.
        assert_eq!(mb.join(n), Err(MailboxError::AlreadyJoined));
        assert_eq!(mb.join(n), Err(MailboxError::NotFound));
    }
}
