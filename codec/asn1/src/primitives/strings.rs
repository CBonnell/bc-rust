use core::str;

use super::{ContentCodec, fixed_tag};
use crate::util::write_slice;
use crate::{AlphabetConstrainable, Error, Rules, SizeConstrainable, Tag, ValueError};

/// An OCTET STRING.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct OctetString<'a>(&'a [u8]);

impl<'a> OctetString<'a> {
    /// Wraps `bytes`.
    pub const fn new(bytes: &'a [u8]) -> Self {
        OctetString(bytes)
    }

    /// The octets.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

fixed_tag!(OctetString<'_>, Tag::OCTET_STRING);

impl<'a> ContentCodec<'a> for OctetString<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        Ok(OctetString(content))
    }

    fn content_len(&self) -> usize {
        self.0.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.0)
    }
}

impl SizeConstrainable for OctetString<'_> {
    fn constraint_size(&self) -> u64 {
        crate::util::saturating_to_u64(self.0.len())
    }
}

/// A UTF8String.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Utf8String<'a>(&'a str);

impl<'a> Utf8String<'a> {
    /// Wraps `s`.
    pub const fn new(s: &'a str) -> Self {
        Utf8String(s)
    }

    /// The text.
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

fixed_tag!(Utf8String<'_>, Tag::UTF8_STRING);

impl<'a> ContentCodec<'a> for Utf8String<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        str::from_utf8(content).map(Utf8String).map_err(|_| ValueError::InvalidCharacterEncoding)
    }

    fn content_len(&self) -> usize {
        self.0.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.0.as_bytes())
    }
}

impl SizeConstrainable for Utf8String<'_> {
    fn constraint_size(&self) -> u64 {
        crate::util::saturating_to_u64(self.0.chars().count())
    }
}

impl AlphabetConstrainable for Utf8String<'_> {
    fn constraint_chars(&self) -> impl Iterator<Item = char> {
        self.0.chars()
    }
}

macro_rules! ascii_string {
    ($(#[$m:meta])* $name:ident, $tag:expr, |$b:ident| $allowed:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Hash, Debug)]
        pub struct $name<'a>(&'a str);

        impl<'a> $name<'a> {
            /// Wraps `s` after checking every character against the type's alphabet.
            ///
            /// # Errors
            ///
            /// [`ValueError::NotInAlphabet`].
            pub fn new(s: &'a str) -> Result<Self, ValueError> {
                if s.bytes().all(Self::is_allowed_byte) {
                    Ok($name(s))
                } else {
                    Err(ValueError::NotInAlphabet)
                }
            }

            /// Whether `b` is in the type's alphabet.
            pub(crate) fn is_allowed_byte($b: u8) -> bool {
                $allowed
            }

            /// The text.
            pub const fn as_str(&self) -> &'a str {
                self.0
            }
        }

        fixed_tag!($name<'_>, $tag);

        impl<'a> ContentCodec<'a> for $name<'a> {
            fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
                if !content.iter().copied().all(Self::is_allowed_byte) {
                    return Err(ValueError::NotInAlphabet);
                }
                str::from_utf8(content)
                    .map($name)
                    .map_err(|_| ValueError::InvalidCharacterEncoding)
            }

            fn content_len(&self) -> usize {
                self.0.len()
            }

            fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
                write_slice(out, self.0.as_bytes())
            }
        }

        impl SizeConstrainable for $name<'_> {
            fn constraint_size(&self) -> u64 {
                crate::util::saturating_to_u64(self.0.len())
            }
        }

        impl AlphabetConstrainable for $name<'_> {
            fn constraint_chars(&self) -> impl Iterator<Item = char> {
                self.0.chars()
            }
        }
    };
}

ascii_string!(
    /// A PrintableString.
    PrintableString,
    Tag::PRINTABLE_STRING,
    |b| b.is_ascii_alphanumeric()
        || matches!(
            b,
            b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
);
ascii_string!(
    /// An IA5String.
    Ia5String, Tag::IA5_STRING, |b| b < 0x80
);
ascii_string!(
    /// A VisibleString.
    VisibleString, Tag::VISIBLE_STRING, |b| matches!(b, 0x20..=0x7E)
);
ascii_string!(
    /// A NumericString.
    NumericString, Tag::NUMERIC_STRING, |b| b.is_ascii_digit() || b == b' '
);

/// A TeletexString (T61String): opaque bytes with no interpretation. Its use is discouraged.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TeletexString<'a>(&'a [u8]);

impl<'a> TeletexString<'a> {
    /// Wraps `bytes`.
    pub const fn new(bytes: &'a [u8]) -> Self {
        TeletexString(bytes)
    }

    /// The octets.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

fixed_tag!(TeletexString<'_>, Tag::TELETEX_STRING);

impl<'a> ContentCodec<'a> for TeletexString<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        Ok(TeletexString(content))
    }

    fn content_len(&self) -> usize {
        self.0.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.0)
    }
}

impl SizeConstrainable for TeletexString<'_> {
    fn constraint_size(&self) -> u64 {
        crate::util::saturating_to_u64(self.0.len())
    }
}

/// A BMPString: UCS-2 big-endian with no surrogates.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BmpString<'a>(&'a [u8]);

impl<'a> BmpString<'a> {
    /// Wraps UCS-2 big-endian `bytes` after validating them.
    ///
    /// # Errors
    ///
    /// [`ValueError::InvalidLength`] for an odd length and
    /// [`ValueError::InvalidCharacterEncoding`] for a surrogate.
    pub fn new(bytes: &'a [u8]) -> Result<Self, ValueError> {
        let (units, remainder) = bytes.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(ValueError::InvalidLength);
        }
        units.iter().try_for_each(|u| Self::decode_unit(*u).map(drop))?;
        Ok(BmpString(bytes))
    }

    /// Decodes one big-endian UCS-2 code unit.
    pub(crate) fn decode_unit(unit: [u8; 2]) -> Result<char, ValueError> {
        char::from_u32(u32::from(u16::from_be_bytes(unit)))
            .ok_or(ValueError::InvalidCharacterEncoding)
    }

    /// The raw big-endian octets.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The characters.
    pub fn chars(&self) -> impl Iterator<Item = Result<char, ValueError>> + 'a {
        self.0.as_chunks::<2>().0.iter().map(|u| Self::decode_unit(*u))
    }
}

fixed_tag!(BmpString<'_>, Tag::BMP_STRING);

impl<'a> ContentCodec<'a> for BmpString<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        BmpString::new(content)
    }

    fn content_len(&self) -> usize {
        self.0.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.0)
    }
}

impl SizeConstrainable for BmpString<'_> {
    fn constraint_size(&self) -> u64 {
        crate::util::saturating_to_u64(self.0.len() / 2)
    }
}

impl AlphabetConstrainable for BmpString<'_> {
    fn constraint_chars(&self) -> impl Iterator<Item = char> {
        self.chars().map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
    }
}

/// A UniversalString: UCS-4 big-endian, every value a Unicode scalar value.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct UniversalString<'a>(&'a [u8]);

impl<'a> UniversalString<'a> {
    /// Wraps UCS-4 big-endian `bytes` after validating them.
    ///
    /// # Errors
    ///
    /// [`ValueError::InvalidLength`] if the length isn't a multiple of 4 and
    /// [`ValueError::InvalidCharacterEncoding`] for a value that isn't a scalar value.
    pub fn new(bytes: &'a [u8]) -> Result<Self, ValueError> {
        let (units, remainder) = bytes.as_chunks::<4>();
        if !remainder.is_empty() {
            return Err(ValueError::InvalidLength);
        }
        units.iter().try_for_each(|u| Self::decode_unit(*u).map(drop))?;
        Ok(UniversalString(bytes))
    }

    /// Decodes one big-endian UCS-4 value.
    pub(crate) fn decode_unit(unit: [u8; 4]) -> Result<char, ValueError> {
        char::from_u32(u32::from_be_bytes(unit)).ok_or(ValueError::InvalidCharacterEncoding)
    }

    /// The raw big-endian octets.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The characters.
    pub fn chars(&self) -> impl Iterator<Item = Result<char, ValueError>> + 'a {
        self.0.as_chunks::<4>().0.iter().map(|u| Self::decode_unit(*u))
    }
}

fixed_tag!(UniversalString<'_>, Tag::UNIVERSAL_STRING);

impl<'a> ContentCodec<'a> for UniversalString<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        UniversalString::new(content)
    }

    fn content_len(&self) -> usize {
        self.0.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.0)
    }
}

impl SizeConstrainable for UniversalString<'_> {
    fn constraint_size(&self) -> u64 {
        crate::util::saturating_to_u64(self.0.len() / 4)
    }
}

impl AlphabetConstrainable for UniversalString<'_> {
    fn constraint_chars(&self) -> impl Iterator<Item = char> {
        self.chars().map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
    }
}
