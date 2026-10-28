use super::{ContentCodec, fixed_tag};
use crate::util::write_slice;
use crate::{Error, Rules, Tag, ValueError};

/// An INTEGER of any length, borrowing its minimal two's complement contents.
///
/// Converts to Rust integers with `TryFrom`, failing with
/// [`ValueError::IntegerOutOfRange`] when the value doesn't fit.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Int<'a> {
    bytes: &'a [u8],
}

fn check_minimal(bytes: &[u8]) -> Result<(), ValueError> {
    match bytes {
        [] => Err(ValueError::IntegerEmpty),
        [0x00, second, ..] if second & 0x80 == 0 => Err(ValueError::IntegerNotMinimal),
        [0xFF, second, ..] if second & 0x80 != 0 => Err(ValueError::IntegerNotMinimal),
        _ => Ok(()),
    }
}

impl<'a> Int<'a> {
    /// Wraps minimal two's complement `bytes`.
    ///
    /// # Errors
    ///
    /// [`ValueError::IntegerEmpty`] or [`ValueError::IntegerNotMinimal`].
    pub fn new(bytes: &'a [u8]) -> Result<Self, ValueError> {
        check_minimal(bytes)?;
        Ok(Int { bytes })
    }

    /// The two's complement contents.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Whether the value is negative.
    pub fn is_negative(&self) -> bool {
        self.bytes.first().is_some_and(|b| b & 0x80 != 0)
    }

    /// The magnitude of a non-negative value, without the leading `0x00` that keeps it
    /// non-negative.
    ///
    /// # Errors
    ///
    /// [`ValueError::IntegerOutOfRange`] on a negative value.
    pub fn unsigned_bytes(&self) -> Result<&'a [u8], ValueError> {
        if self.is_negative() {
            return Err(ValueError::IntegerOutOfRange);
        }
        match self.bytes {
            [0x00, rest @ ..] if !rest.is_empty() => Ok(rest),
            all => Ok(all),
        }
    }

    fn to_i128(&self) -> Result<i128, ValueError> {
        if self.bytes.len() > 16 {
            return Err(ValueError::IntegerOutOfRange);
        }
        let seed = if self.is_negative() { -1i128 } else { 0 };
        Ok(self.bytes.iter().fold(seed, |acc, &b| (acc << 8) | i128::from(b)))
    }

    fn to_u128(&self) -> Result<u128, ValueError> {
        let magnitude = self.unsigned_bytes()?;
        if magnitude.len() > 16 {
            return Err(ValueError::IntegerOutOfRange);
        }
        Ok(magnitude.iter().fold(0u128, |acc, &b| (acc << 8) | u128::from(b)))
    }
}

macro_rules! int_try_from {
    ($via:ident: $($t:ty),*) => {$(
        impl<'a> TryFrom<Int<'a>> for $t {
            type Error = ValueError;
            fn try_from(v: Int<'a>) -> Result<Self, ValueError> {
                <$t>::try_from(&v)
            }
        }
        impl<'a, 'b> TryFrom<&'b Int<'a>> for $t {
            type Error = ValueError;
            fn try_from(v: &'b Int<'a>) -> Result<Self, ValueError> {
                <$t>::try_from(v.$via()?).map_err(|_| ValueError::IntegerOutOfRange)
            }
        }
        impl<'a> TryFrom<Enumerated<'a>> for $t {
            type Error = ValueError;
            fn try_from(v: Enumerated<'a>) -> Result<Self, ValueError> {
                <$t>::try_from(&v.0)
            }
        }
        impl<'a, 'b> TryFrom<&'b Enumerated<'a>> for $t {
            type Error = ValueError;
            fn try_from(v: &'b Enumerated<'a>) -> Result<Self, ValueError> {
                <$t>::try_from(&v.0)
            }
        }
    )*};
}
int_try_from!(to_i128: i8, i16, i32, i64, i128, isize);
int_try_from!(to_u128: u8, u16, u32, u64, usize);

impl<'a, 'b> TryFrom<&'b Int<'a>> for u128 {
    type Error = ValueError;
    fn try_from(v: &'b Int<'a>) -> Result<Self, ValueError> {
        v.to_u128()
    }
}
impl<'a> TryFrom<Int<'a>> for u128 {
    type Error = ValueError;
    fn try_from(v: Int<'a>) -> Result<Self, ValueError> {
        v.to_u128()
    }
}
impl<'a> TryFrom<Enumerated<'a>> for u128 {
    type Error = ValueError;
    fn try_from(v: Enumerated<'a>) -> Result<Self, ValueError> {
        v.0.to_u128()
    }
}
impl<'a, 'b> TryFrom<&'b Enumerated<'a>> for u128 {
    type Error = ValueError;
    fn try_from(v: &'b Enumerated<'a>) -> Result<Self, ValueError> {
        v.0.to_u128()
    }
}

fixed_tag!(Int<'_>, Tag::INTEGER);

impl<'a> ContentCodec<'a> for Int<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        Int::new(content)
    }

    fn content_len(&self) -> usize {
        self.bytes.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.bytes)
    }
}

/// An ENUMERATED value, wrapping its [`Int`] contents.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Enumerated<'a>(Int<'a>);

impl<'a> Enumerated<'a> {
    /// Wraps minimal two's complement `bytes`.
    ///
    /// # Errors
    ///
    /// [`ValueError::IntegerEmpty`] or [`ValueError::IntegerNotMinimal`].
    pub fn new(bytes: &'a [u8]) -> Result<Self, ValueError> {
        Int::new(bytes).map(Enumerated)
    }

    /// The value as an [`Int`].
    pub const fn as_int(&self) -> &Int<'a> {
        &self.0
    }
}

fixed_tag!(Enumerated<'_>, Tag::ENUMERATED);

impl<'a> ContentCodec<'a> for Enumerated<'a> {
    fn decode_content(content: &'a [u8], rules: Rules) -> Result<Self, ValueError> {
        Int::decode_content(content, rules).map(Enumerated)
    }

    fn content_len(&self) -> usize {
        self.0.content_len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.0.encode_content(out)
    }
}

/// Minimal two's complement of a signed value.
fn signed_bytes(v: i128) -> ([u8; 16], usize) {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while let Some(window) = bytes.get(start..start + 2) {
        match window {
            [0x00, b] if b & 0x80 == 0 => start += 1,
            [0xFF, b] if b & 0x80 != 0 => start += 1,
            _ => break,
        }
    }
    (bytes, start)
}

/// Minimal two's complement of an unsigned value, with a leading zero when the top bit is set.
fn unsigned_bytes(v: u128) -> ([u8; 17], usize) {
    let mut out = [0u8; 17];
    if let Some(tail) = out.get_mut(1..) {
        tail.copy_from_slice(&v.to_be_bytes());
    }
    let mut start = 0;
    while let Some(window) = out.get(start..start + 2) {
        match window {
            [0x00, b] if b & 0x80 == 0 => start += 1,
            _ => break,
        }
    }
    (out, start)
}

macro_rules! native_int {
    (signed: $($t:ty),*) => {$(
        fixed_tag!($t, Tag::INTEGER);
        impl<'a> ContentCodec<'a> for $t {
            fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
                <$t>::try_from(&Int::new(content)?)
            }
            fn content_len(&self) -> usize {
                let (bytes, start) = signed_bytes(i128::from(*self));
                bytes.len() - start
            }
            fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
                let (bytes, start) = signed_bytes(i128::from(*self));
                write_slice(out, bytes.get(start..).unwrap_or(&[]))
            }
        }
    )*};
    (unsigned: $($t:ty),*) => {$(
        fixed_tag!($t, Tag::INTEGER);
        impl<'a> ContentCodec<'a> for $t {
            fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
                <$t>::try_from(&Int::new(content)?)
            }
            fn content_len(&self) -> usize {
                let (bytes, start) = unsigned_bytes(u128::from(*self));
                bytes.len() - start
            }
            fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
                let (bytes, start) = unsigned_bytes(u128::from(*self));
                write_slice(out, bytes.get(start..).unwrap_or(&[]))
            }
        }
    )*};
}
native_int!(signed: i8, i16, i32, i64);
native_int!(unsigned: u8, u16, u32, u64);

fixed_tag!(i128, Tag::INTEGER);
impl<'a> ContentCodec<'a> for i128 {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        i128::try_from(&Int::new(content)?)
    }
    fn content_len(&self) -> usize {
        let (bytes, start) = signed_bytes(*self);
        bytes.len() - start
    }
    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        let (bytes, start) = signed_bytes(*self);
        write_slice(out, bytes.get(start..).unwrap_or(&[]))
    }
}

fixed_tag!(u128, Tag::INTEGER);
impl<'a> ContentCodec<'a> for u128 {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        u128::try_from(&Int::new(content)?)
    }
    fn content_len(&self) -> usize {
        let (bytes, start) = unsigned_bytes(*self);
        bytes.len() - start
    }
    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        let (bytes, start) = unsigned_bytes(*self);
        write_slice(out, bytes.get(start..).unwrap_or(&[]))
    }
}
