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

    #[tokio::test]
    async fn garbage_is_an_error_not_a_panic() {
        let (a, b) = tokio::io::duplex(4096);
        let mut a = FramedConn::new(a);
        let mut b = FramedConn::new(b);
        a.send(&vec![0xffu8; 40]).await.unwrap();
        assert!(b.recv::<Request>().await.is_err());
    }
}
