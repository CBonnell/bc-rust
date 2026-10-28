//! The streaming encoder.

use crate::util::{insufficient, saturating_to_u64};
use crate::{Error, ErrorKind, Identifier, Length, Rules};

#[derive(Clone, Copy, Debug)]
struct Frame {
    constructed: bool,
    remaining: Option<u64>,
}

/// Writes TLVs piece by piece, mirroring the tokenizer's events, for large content such as
/// CMS `eContent` or firmware.
///
/// Each call writes into `out` and returns the bytes written, or fails with
/// [`ErrorKind::InsufficientSize`] without writing or changing state.
#[derive(Clone, Debug)]
pub struct StreamEncoder<const DEPTH: usize = 32> {
    rules: Rules,
    stack: [Frame; DEPTH],
    len: usize,
}

impl<const DEPTH: usize> StreamEncoder<DEPTH> {
    /// An encoder that emits `rules`. Only BER permits indefinite lengths.
    pub fn new(rules: Rules) -> Self {
        StreamEncoder {
            rules,
            stack: [Frame { constructed: false, remaining: Some(0) }; DEPTH],
            len: 0,
        }
    }

    /// The number of values currently open.
    pub fn depth(&self) -> usize {
        self.len
    }

    fn open_frames(&self) -> &[Frame] {
        self.stack.get(..self.len).unwrap_or(&[])
    }

    /// Checks that `bytes` fit the nearest definite-length value among the first `below`
    /// open ones.
    fn check_charge(&self, below: usize, bytes: u64) -> Result<(), Error> {
        let frames = self.stack.get(..below).unwrap_or(&[]);
        match frames.iter().rev().find_map(|f| f.remaining) {
            Some(remaining) if bytes > remaining => {
                Err(Error::new(ErrorKind::ChildOverrunsParent, 0))
            }
            _ => Ok(()),
        }
    }

    fn charge(&mut self, below: usize, bytes: u64) {
        let frames = self.stack.get_mut(..below).unwrap_or_default();
        if let Some(remaining) = frames.iter_mut().rev().find_map(|f| f.remaining.as_mut()) {
            *remaining -= bytes;
        }
    }

    /// Writes the header of a new value.
    ///
    /// [`Length::Indefinite`] is allowed only under BER and only on constructed values.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::IndefiniteNotAllowed`], [`ErrorKind::IndefiniteOnPrimitive`],
    /// [`ErrorKind::InvalidState`] inside a primitive, [`ErrorKind::DepthExceeded`],
    /// [`ErrorKind::ChildOverrunsParent`] if the value doesn't fit its definite-length parent,
    /// and [`ErrorKind::InsufficientSize`].
    pub fn begin(&mut self, id: Identifier, len: Length, out: &mut [u8]) -> Result<usize, Error> {
        if len == Length::Indefinite {
            if self.rules != Rules::Ber {
                return Err(Error::new(ErrorKind::IndefiniteNotAllowed, 0));
            }
            if !id.constructed {
                return Err(Error::new(ErrorKind::IndefiniteOnPrimitive, 0));
            }
        }
        if self.open_frames().last().is_some_and(|f| !f.constructed) {
            return Err(Error::new(ErrorKind::InvalidState, 0));
        }
        if self.len >= DEPTH {
            return Err(Error::new(ErrorKind::DepthExceeded, 0));
        }
        let header_len = id.encoded_len() + len.encoded_len();
        let total = saturating_to_u64(header_len).saturating_add(match len {
            Length::Definite(l) => l,
            Length::Indefinite => 0,
        });
        self.check_charge(self.len, total)?;
        let dst = out.get_mut(..header_len).ok_or_else(|| insufficient(header_len, 0))?;
        let (id_out, len_out) =
            dst.split_at_mut_checked(id.encoded_len()).ok_or(insufficient(header_len, 0))?;
        id.encode(id_out)?;
        len.encode(len_out)?;
        self.charge(self.len, total);
        let frame = Frame {
            constructed: id.constructed,
            remaining: match len {
                Length::Definite(l) => Some(l),
                Length::Indefinite => None,
            },
        };
        if let Some(slot) = self.stack.get_mut(self.len) {
            *slot = frame;
        }
        self.len += 1;
        Ok(header_len)
    }

    /// Writes `bytes` as primitive contents.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidState`] unless a primitive value is open,
    /// [`ErrorKind::ChildOverrunsParent`] if the contents would exceed the declared length,
    /// and [`ErrorKind::InsufficientSize`].
    pub fn content(&mut self, bytes: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let Some(&frame) = self.open_frames().last() else {
            return Err(Error::new(ErrorKind::InvalidState, 0));
        };
        if frame.constructed {
            return Err(Error::new(ErrorKind::InvalidState, 0));
        }
        if frame.remaining.is_some_and(|r| saturating_to_u64(bytes.len()) > r) {
            return Err(Error::new(ErrorKind::ChildOverrunsParent, 0));
        }
        let dst = out.get_mut(..bytes.len()).ok_or_else(|| insufficient(bytes.len(), 0))?;
        dst.copy_from_slice(bytes);
        if let Some(top) = self.len.checked_sub(1).and_then(|i| self.stack.get_mut(i))
            && let Some(r) = top.remaining.as_mut()
        {
            *r -= saturating_to_u64(bytes.len());
        }
        Ok(bytes.len())
    }

    /// Closes the innermost value, writing `00 00` if its length is indefinite.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidState`] if nothing is open, [`ErrorKind::Truncated`] if a
    /// definite length wasn't filled exactly, [`ErrorKind::ChildOverrunsParent`] and
    /// [`ErrorKind::InsufficientSize`].
    pub fn end(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let Some(&frame) = self.open_frames().last() else {
            return Err(Error::new(ErrorKind::InvalidState, 0));
        };
        let written = match frame.remaining {
            Some(0) => 0,
            Some(_) => return Err(Error::new(ErrorKind::Truncated, 0)),
            None => {
                self.check_charge(self.len - 1, 2)?;
                let dst = out.get_mut(..2).ok_or_else(|| insufficient(2, 0))?;
                dst.fill(0);
                self.charge(self.len - 1, 2);
                2
            }
        };
        self.len -= 1;
        Ok(written)
    }
}
