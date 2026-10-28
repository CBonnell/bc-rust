use super::{ContentCodec, fixed_tag};
use crate::{Error, Rules, Tag, ValueError};

/// A BIT STRING: data octets plus the number of unused bits in the last one.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BitString<'a> {
    unused_bits: u8,
    data: &'a [u8],
}

impl<'a> BitString<'a> {
    /// Builds a bit string from its parts.
    ///
    /// # Errors
    ///
    /// [`ValueError::BitStringUnusedBits`] if `unused_bits` exceeds 7, or is non-zero with no
    /// data octets.
    pub fn new(unused_bits: u8, data: &'a [u8]) -> Result<Self, ValueError> {
        if unused_bits > 7 || (data.is_empty() && unused_bits != 0) {
            return Err(ValueError::BitStringUnusedBits);
        }
        Ok(BitString { unused_bits, data })
    }

    /// The number of unused bits in the last data octet.
    pub const fn unused_bits(&self) -> u8 {
        self.unused_bits
    }

    /// The data octets.
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The number of bits.
    pub const fn len_bits(&self) -> usize {
        self.data.len() * 8 - self.unused_bits as usize
    }

    /// Bit `i`, counting from the most significant bit of the first octet; `None` past the
    /// end.
    pub fn bit(&self, i: usize) -> Option<bool> {
        if i >= self.len_bits() {
            return None;
        }
        let octet = self.data.get(i / 8)?;
        Some(octet >> (7 - i % 8) & 1 == 1)
    }

    /// The indices of the set bits, in ascending order.
    pub fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len_bits()).filter(|&i| self.bit(i) == Some(true))
    }

    fn padding_is_zero(&self) -> bool {
        match self.data.last() {
            Some(last) => last & ((1u8 << self.unused_bits) - 1) == 0,
            None => true,
        }
    }
}

fixed_tag!(BitString<'_>, Tag::BIT_STRING);

impl<'a> ContentCodec<'a> for BitString<'a> {
    fn decode_content(content: &'a [u8], rules: Rules) -> Result<Self, ValueError> {
        let (&unused, data) = content.split_first().ok_or(ValueError::BitStringUnusedBits)?;
        let bits = BitString::new(unused, data)?;
        if rules == Rules::Der && !bits.padding_is_zero() {
            return Err(ValueError::BitStringPaddingNotZero);
        }
        Ok(bits)
    }

    fn content_len(&self) -> usize {
        1 + self.data.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.padding_is_zero() {
            return Err(Error::value(ValueError::BitStringPaddingNotZero, 0));
        }
        let total = self.content_len();
        let dst = out.get_mut(..total).ok_or(crate::util::insufficient(total, 0))?;
        match dst.split_first_mut() {
            Some((first, rest)) => {
                *first = self.unused_bits;
                rest.copy_from_slice(self.data);
            }
            None => return Err(crate::util::insufficient(total, 0)),
        }
        Ok(total)
    }
}

/// A named bit list such as KeyUsage: a [`BitString`] that under DER has no trailing zero
/// bits.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct NamedBits<'a>(BitString<'a>);

impl<'a> NamedBits<'a> {
    /// Builds a named bit list from its parts.
    ///
    /// # Errors
    ///
    /// The errors of [`BitString::new`].
    pub fn new(unused_bits: u8, data: &'a [u8]) -> Result<Self, ValueError> {
        BitString::new(unused_bits, data).map(NamedBits)
    }

    /// The underlying bit string.
    pub const fn as_bit_string(&self) -> &BitString<'a> {
        &self.0
    }

    /// Whether bit `i` is set.
    pub fn is_set(&self, i: usize) -> bool {
        self.0.bit(i) == Some(true)
    }

    fn check_trailing(&self) -> Result<(), ValueError> {
        let len = self.0.len_bits();
        if len > 0 && self.0.bit(len - 1) != Some(true) {
            return Err(ValueError::NamedBitsTrailingZero);
        }
        Ok(())
    }
}

fixed_tag!(NamedBits<'_>, Tag::BIT_STRING);

impl<'a> ContentCodec<'a> for NamedBits<'a> {
    fn decode_content(content: &'a [u8], rules: Rules) -> Result<Self, ValueError> {
        let bits = NamedBits(BitString::decode_content(content, rules)?);
        if rules == Rules::Der {
            bits.check_trailing()?;
        }
        Ok(bits)
    }

    fn content_len(&self) -> usize {
        self.0.content_len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check_trailing().map_err(|e| Error::value(e, 0))?;
        self.0.encode_content(out)
    }
}
