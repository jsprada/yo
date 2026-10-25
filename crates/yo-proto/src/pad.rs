//! Length padding applied to plaintext *before* end-to-end encryption, so the
//! server only learns which size bucket a message falls into.

const BUCKETS: &[usize] = &[256, 1024, 4096, 16384, 65536, 262144];

/// Largest payload that fits in the biggest bucket.
pub const MAX_PAYLOAD: usize = 262144 - 4;

pub fn pad(data: &[u8]) -> Option<Vec<u8>> {
    let need = data.len() + 4;
    let size = *BUCKETS.iter().find(|&&b| b >= need)?;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out.resize(size, 0);
    Some(out)
}

pub fn unpad(data: &[u8]) -> Option<&[u8]> {
    let len = u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as usize;
    data.get(4..4 + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets() {
        assert_eq!(pad(b"hi").unwrap().len(), 256);
        assert_eq!(pad(&[1; 300]).unwrap().len(), 1024);
        assert_eq!(unpad(&pad(b"hello").unwrap()).unwrap(), b"hello");
        assert!(pad(&vec![0; MAX_PAYLOAD + 1]).is_none());
        assert!(unpad(&[9, 9, 9, 9, 1]).is_none());
    }
}
