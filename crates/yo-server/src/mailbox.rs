//! In-memory relay mailboxes for the invite / link key exchange.
//!
//! Mailboxes only ever hold SPAKE2 messages and PAKE-encrypted payloads, live
//! for at most ten minutes, accept a single joiner, and are never written to
//! disk. Every mailbox is bound to the device that opened it and the device
//! that joined it: nobody else can write to it, read from it or close it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use yo_proto::DeviceId;
use yo_proto::msg::Side;

pub const MAILBOX_TTL: Duration = Duration::from_secs(600);
const MAX_MESSAGES_PER_SIDE: usize = 8;
/// SPAKE2 messages are 33 bytes; a `yo link` payload is a few KiB.
const MAX_MESSAGE: usize = 16 * 1024;
/// Nameplates are at least five digits, so a pending invite is not easy to
/// stumble upon (see SECURITY_REVIEW.md, M-1).
const MIN_NAMEPLATE: u32 = 10_000;
const INITIAL_SPAN: u32 = 90_000;

struct Mailbox {
    created: Instant,
    opener_dev: DeviceId,
    joiner_dev: Option<DeviceId>,
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

    fn role(&self, dev: &DeviceId) -> Option<Side> {
        if self.opener_dev == *dev {
            Some(Side::Opener)
        } else if self.joiner_dev.as_ref() == Some(dev) {
            Some(Side::Joiner)
        } else {
            None
        }
    }
}

pub struct Mailboxes {
    boxes: HashMap<u32, Mailbox>,
    max: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MailboxError {
    NotFound,
    /// Another device already joined.
    AlreadyJoined,
    TooLarge,
    /// The caller is not a participant (or is trying to act as the wrong side).
    Unauthorized,
    /// The server-wide mailbox cap is reached.
    Full,
}

impl Mailboxes {
    pub fn new(max: usize) -> Self {
        Mailboxes { boxes: HashMap::new(), max }
    }

    pub fn open(&mut self, me: DeviceId) -> Result<u32, MailboxError> {
        self.expire();
        if self.boxes.len() >= self.max {
            return Err(MailboxError::Full);
        }
        // Five digits while the server is quiet, more if it is busy.
        let mut span = INITIAL_SPAN;
        loop {
            for _ in 0..32 {
                let n = MIN_NAMEPLATE + getrandom::u32().expect("os rng") % span;
                if let std::collections::hash_map::Entry::Vacant(e) = self.boxes.entry(n) {
                    e.insert(Mailbox {
                        created: Instant::now(),
                        opener_dev: me,
                        joiner_dev: None,
                        opener: vec![],
                        joiner: vec![],
                        notify: Arc::new(Notify::new()),
                    });
                    return Ok(n);
                }
            }
            span = span.saturating_mul(10);
        }
    }

    pub fn join(&mut self, n: u32, me: DeviceId) -> Result<(), MailboxError> {
        let m = self.boxes.get_mut(&n).ok_or(MailboxError::NotFound)?;
        if m.opener_dev == me {
            return Err(MailboxError::Unauthorized);
        }
        match m.joiner_dev {
            None => {
                m.joiner_dev = Some(me);
                Ok(())
            }
            Some(j) if j == me => Ok(()),
            // One joiner only: the first to arrive gets the single SPAKE2
            // attempt; nobody else can touch the mailbox.
            Some(_) => Err(MailboxError::AlreadyJoined),
        }
    }

    pub fn put(&mut self, n: u32, me: DeviceId, side: Side, msg: Vec<u8>) -> Result<(), MailboxError> {
        if msg.len() > MAX_MESSAGE {
            return Err(MailboxError::TooLarge);
        }
        let m = self.boxes.get_mut(&n).ok_or(MailboxError::NotFound)?;
        if m.role(&me) != Some(side) {
            return Err(MailboxError::Unauthorized);
        }
        let q = m.side(side);
        if q.len() >= MAX_MESSAGES_PER_SIDE {
            return Err(MailboxError::TooLarge);
        }
        q.push(msg);
        m.notify.notify_waiters();
        Ok(())
    }

    /// Message `index` from the side opposite `side`, plus a handle to wait
    /// on when it is not there yet. `me` must be the device acting as `side`.
    pub fn get(
        &mut self,
        n: u32,
        me: DeviceId,
        side: Side,
        index: u32,
    ) -> Result<(Option<Vec<u8>>, Arc<Notify>), MailboxError> {
        let m = self.boxes.get_mut(&n).ok_or(MailboxError::NotFound)?;
        if m.role(&me) != Some(side) {
            return Err(MailboxError::Unauthorized);
        }
        let notify = m.notify.clone();
        let msg = m.side(side.other()).get(index as usize).cloned();
        Ok((msg, notify))
    }

    /// Close a mailbox; only its participants may.
    pub fn close(&mut self, n: u32, me: DeviceId) -> Result<(), MailboxError> {
        let m = self.boxes.get(&n).ok_or(MailboxError::NotFound)?;
        if m.role(&me).is_none() {
            return Err(MailboxError::Unauthorized);
        }
        self.remove(n);
        Ok(())
    }

    fn remove(&mut self, n: u32) {
        if let Some(m) = self.boxes.remove(&n) {
            m.notify.notify_waiters();
        }
    }

    pub fn len(&self) -> usize {
        self.boxes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty()
    }

    pub fn expire(&mut self) {
        let dead: Vec<u32> =
            self.boxes.iter().filter(|(_, m)| m.created.elapsed() > MAILBOX_TTL).map(|(n, _)| *n).collect();
        for n in dead {
            self.remove(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: DeviceId = DeviceId([1; 16]);
    const B: DeviceId = DeviceId([2; 16]);
    const EVE: DeviceId = DeviceId([3; 16]);

    #[test]
    fn participants_only() {
        let mut mb = Mailboxes::new(10);
        let n = mb.open(A).unwrap();
        assert!((MIN_NAMEPLATE..MIN_NAMEPLATE + INITIAL_SPAN).contains(&n));
        mb.put(n, A, Side::Opener, b"a0".to_vec()).unwrap();

        // A stranger can neither write, read nor close.
        assert_eq!(mb.put(n, EVE, Side::Joiner, b"x".to_vec()), Err(MailboxError::Unauthorized));
        assert_eq!(mb.get(n, EVE, Side::Joiner, 0).err(), Some(MailboxError::Unauthorized));
        assert_eq!(mb.close(n, EVE), Err(MailboxError::Unauthorized));
        // The opener can't act as the joiner, and can't join its own invite.
        assert_eq!(mb.put(n, A, Side::Joiner, b"x".to_vec()), Err(MailboxError::Unauthorized));
        assert_eq!(mb.join(n, A), Err(MailboxError::Unauthorized));

        mb.join(n, B).unwrap();
        assert_eq!(mb.get(n, B, Side::Joiner, 0).unwrap().0.unwrap(), b"a0");
        assert!(mb.get(n, A, Side::Opener, 0).unwrap().0.is_none());
        // A second joiner is refused, but the mailbox stays intact.
        assert_eq!(mb.join(n, EVE), Err(MailboxError::AlreadyJoined));
        assert!(mb.join(n, B).is_ok(), "rejoin by the same device is harmless");
        mb.put(n, B, Side::Joiner, b"b0".to_vec()).unwrap();
        assert_eq!(mb.get(n, A, Side::Opener, 0).unwrap().0.unwrap(), b"b0");
        mb.close(n, B).unwrap();
        assert_eq!(mb.join(n, B), Err(MailboxError::NotFound));
    }

    #[test]
    fn cap_and_size() {
        let mut mb = Mailboxes::new(2);
        let n1 = mb.open(A).unwrap();
        mb.open(A).unwrap();
        assert_eq!(mb.open(A), Err(MailboxError::Full));
        assert_eq!(mb.put(n1, A, Side::Opener, vec![0; MAX_MESSAGE + 1]), Err(MailboxError::TooLarge));
        mb.close(n1, A).unwrap();
        assert!(mb.open(B).is_ok());
    }
}
