//! Length octets.

use crate::util::{insufficient, saturating_to_u64};
use crate::{Error, ErrorKind, Rules};

/// A decoded length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Length {
    /// A definite length in content octets.
    Definite(u64),
    /// The indefinite form, terminated by end-of-contents octets.
    Indefinite,
}

impl Length {
    /// Decodes length octets from the start of `input`, returning the length and the number of
    /// bytes used. Error offsets are relative to `input`.
    ///
    /// BER accepts non-minimal long forms; DER requires the short form below 128, the minimum
    /// number of octets above it, and rejects the indefinite form.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Truncated`], [`ErrorKind::ReservedLengthOctet`],
    /// [`ErrorKind::IndefiniteNotAllowed`], [`ErrorKind::NonMinimalLength`] and
    /// [`ErrorKind::LengthOverflow`].
    pub fn decode(input: &[u8], rules: Rules) -> Result<(Self, usize), Error> {
        let (&first, rest) = input.split_first().ok_or(Error::new(ErrorKind::Truncated, 0))?;
        match first {
            0xFF => Err(Error::new(ErrorKind::ReservedLengthOctet, 0)),
            0x80 if rules == Rules::Der => Err(Error::new(ErrorKind::IndefiniteNotAllowed, 0)),
            0x80 => Ok((Length::Indefinite, 1)),
            b if b < 0x80 => Ok((Length::Definite(u64::from(b)), 1)),
            b => {
                let n = usize::from(b & 0x7F);
                let octets = rest
                    .get(..n)
                    .ok_or(Error::new(ErrorKind::Truncated, saturating_to_u64(input.len())))?;
                if rules == Rules::Der && octets.first() == Some(&0) {
                    return Err(Error::new(ErrorKind::NonMinimalLength, 0));
                }
                let significant = octets.iter().position(|&o| o != 0).unwrap_or(n);
                let digits = octets.get(significant..).unwrap_or(&[]);
                if digits.len() > 8 {
                    return Err(Error::new(ErrorKind::LengthOverflow, 0));
                }
                let value = digits.iter().fold(0u64, |acc, &o| (acc << 8) | u64::from(o));
                if rules == Rules::Der && value < 128 {
                    return Err(Error::new(ErrorKind::NonMinimalLength, 0));
                }
                Ok((Length::Definite(value), 1 + n))
            }
        }
    }

    /// Encodes the length in minimal form (`0x80` for [`Length::Indefinite`]) and returns the
    /// number of bytes written.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InsufficientSize`] if `out` is too small; nothing is written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len();
        let dst = out.get_mut(..len).ok_or_else(|| insufficient(len, 0))?;
        match (self, dst.split_first_mut()) {
            (Length::Indefinite, Some((first, _))) => *first = 0x80,
            (Length::Definite(v), Some((first, _))) if *v < 128 => *first = *v as u8,
            (Length::Definite(v), Some((first, rest))) => {
                *first = 0x80 | rest.len() as u8;
                let bytes = v.to_be_bytes();
                let skip = bytes.len() - rest.len();
                rest.copy_from_slice(bytes.get(skip..).unwrap_or(&[]));
            }
            (_, None) => return Err(insufficient(len, 0)),
        }
        Ok(len)
    }

    /// The number of bytes [`encode`](Length::encode) writes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Length::Indefinite => 1,
            Length::Definite(v) if *v < 128 => 1,
            Length::Definite(v) => 1 + (8 - (v.leading_zeros() / 8) as usize),
        }
    }
}
