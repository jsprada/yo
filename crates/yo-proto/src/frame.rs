//! Length-prefixed postcard frames over any async byte stream.

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::MAX_FRAME;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("connection closed")]
    Closed,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed frame: {0}")]
    Decode(#[from] postcard::Error),
}

pub struct FramedConn<S> {
    inner: Framed<S, LengthDelimitedCodec>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> FramedConn<S> {
    pub fn new(stream: S) -> Self {
        let codec = LengthDelimitedCodec::builder().max_frame_length(MAX_FRAME).new_codec();
        FramedConn { inner: Framed::new(stream, codec) }
    }

    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<(), FrameError> {
        let bytes = postcard::to_stdvec(value)?;
        self.inner.send(bytes::Bytes::from(bytes)).await?;
        Ok(())
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T, FrameError> {
        match self.inner.next().await {
            Some(Ok(bytes)) => Ok(postcard::from_bytes(&bytes)?),
            Some(Err(e)) => Err(e.into()),
            None => Err(FrameError::Closed),
        }
    }

    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::Request;

    #[tokio::test]
    async fn roundtrip() {
        let (a, b) = tokio::io::duplex(4096);
        let mut a = FramedConn::new(a);
        let mut b = FramedConn::new(b);
        a.send(&Request::Fetch).await.unwrap();
        let r: Request = b.recv().await.unwrap();
        assert_eq!(r, Request::Fetch);
    }

    /// Poor man's fuzzing: random and mutated frames must decode to an error
    /// (or a value), never panic or allocate wildly.
    #[test]
    fn random_input_never_panics() {
        use crate::msg::{Envelope, ServerFrame};
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let valid = postcard::to_stdvec(&ServerFrame::Event(crate::msg::Event::Envelope(Envelope {
            id: 1,
            inbox: crate::InboxId([1; 32]),
            sender: crate::DeviceId([2; 16]),
            from_member: false,
            ts: 3,
            blob: vec![4; 40],
        })))
        .unwrap();
        for i in 0..20_000 {
            let mut buf: Vec<u8> = if i % 2 == 0 {
                (0..(next() % 96)).map(|_| next() as u8).collect()
            } else {
                let mut v = valid.clone();
                let pos = (next() as usize) % v.len();
                v[pos] = next() as u8;
                v
            };
            let _ = postcard::from_bytes::<Request>(&buf);
            let _ = postcard::from_bytes::<ServerFrame>(&buf);
            buf.truncate((next() as usize) % (buf.len() + 1));
            let _ = postcard::from_bytes::<ServerFrame>(&buf);
        }
    }

    #[tokio::test]
    async fn garbage_is_an_error_not_a_panic() {
        let (a, b) = tokio::io::duplex(4096);
        let mut a = FramedConn::new(a);
        let mut b = FramedConn::new(b);
        a.send(&vec![0xffu8; 40]).await.unwrap();
        assert!(b.recv::<Request>().await.is_err());
    }
}
