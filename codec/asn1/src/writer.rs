//! Layer 6: encoding.

use crate::util::{insufficient, saturating_to_u64};
use crate::{Encode, Error, Identifier, Length};

/// A forward writer into a caller-provided slice.
///
/// Every write that doesn't fit fails with
/// [`ErrorKind::InsufficientSize`](crate::ErrorKind::InsufficientSize) and writes nothing.
#[derive(Debug)]
pub struct Writer<'b> {
    out: &'b mut [u8],
    position: usize,
}

impl<'b> Writer<'b> {
    /// A writer at the start of `out`.
    pub fn new(out: &'b mut [u8]) -> Self {
        Writer { out, position: 0 }
    }

    /// Writes the identifier octets and the definite length `len`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InsufficientSize`](crate::ErrorKind::InsufficientSize).
    pub fn write_header(&mut self, id: Identifier, len: u64) -> Result<(), Error> {
        let length = Length::Definite(len);
        let id_len = id.encoded_len();
        let total = id_len + length.encoded_len();
        let dst = self.reserve(total)?;
        let (id_out, length_out) =
            dst.split_at_mut_checked(id_len).ok_or(insufficient(total, 0))?;
        id.encode(id_out)?;
        length.encode(length_out)?;
        Ok(())
    }

    /// Writes `bytes`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InsufficientSize`](crate::ErrorKind::InsufficientSize).
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.reserve(bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    /// The number of bytes written so far.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Writes `item` as one TLV.
    ///
    /// # Errors
    ///
    /// Whatever `item`'s encoder reports.
    pub fn write<T: Encode + ?Sized>(&mut self, item: &T) -> Result<(), Error> {
        item.encode(self)
    }

    pub(crate) fn reserve(&mut self, n: usize) -> Result<&mut [u8], Error> {
        let start = self.position;
        let end = start.saturating_add(n);
        let required = end;
        let dst = self
            .out
            .get_mut(start..end)
            .ok_or_else(|| insufficient(required, saturating_to_u64(start)))?;
        self.position = end;
        Ok(dst)
    }

    pub(crate) fn written(&self) -> &[u8] {
        self.out.get(..self.position).unwrap_or(&[])
    }
}

/// Encodes `value` as DER into `out` and returns the bytes written.
///
/// Computes the encoded length first and fails without writing if `out` is too small.
///
/// # Errors
///
/// [`ErrorKind::InsufficientSize`](crate::ErrorKind::InsufficientSize) with the size needed,
/// and whatever `value`'s encoder reports.
pub fn encode_to_slice<'b, T: Encode + ?Sized>(
    value: &T,
    out: &'b mut [u8],
) -> Result<&'b [u8], Error> {
    let len = value.encoded_len()?;
    let len = usize::try_from(len).map_err(|_| insufficient(usize::MAX, 0))?;
    let dst = out.get_mut(..len).ok_or_else(|| insufficient(len, 0))?;
    let mut writer = Writer::new(dst);
    value.encode(&mut writer)?;
    let written = writer.position();
    if written != len {
        return Err(Error::new(crate::ErrorKind::InvalidState, saturating_to_u64(written)));
    }
    Ok(&*dst)
}
