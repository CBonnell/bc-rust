use crate::{Error, ErrorKind};

pub(crate) fn insufficient(required: usize, offset: u64) -> Error {
    Error::new(ErrorKind::InsufficientSize { required }, offset)
}

/// Copies `src` to the start of `out`, writing nothing if it doesn't fit.
pub(crate) fn write_slice(out: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    match out.get_mut(..src.len()) {
        Some(dst) => {
            dst.copy_from_slice(src);
            Ok(src.len())
        }
        None => Err(insufficient(src.len(), 0)),
    }
}

pub(crate) fn tail(bytes: &[u8], len: usize) -> &[u8] {
    bytes.get(len..).unwrap_or(&[])
}

pub(crate) fn head(bytes: &[u8], len: usize) -> &[u8] {
    bytes.get(..len).unwrap_or(bytes)
}

pub(crate) fn saturating_to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
