//! Layer 4: one type per universal primitive, each with a codec over content bytes.

mod bitstring;
mod boolean;
mod integer;
mod oid;
pub(crate) mod strings;
mod time;

pub use bitstring::{BitString, NamedBits};
pub use integer::{Enumerated, Int};
pub use oid::{Arcs, Null, Oid, RelOid};
pub use strings::{
    BmpString, Ia5String, NumericString, OctetString, PrintableString, TeletexString,
    UniversalString, Utf8String, VisibleString,
};
pub use time::{GeneralizedTime, UtcTime, days_in_month};

use crate::{Error, Rules, ValueError};

/// A codec over the content bytes of one primitive type; the header is already parsed.
///
/// Every implementation also implements [`FixedTag`](crate::FixedTag), and gets
/// [`DecodeValue`](crate::DecodeValue) and [`EncodeValue`](crate::EncodeValue) from blanket
/// impls.
pub trait ContentCodec<'a>: Sized {
    /// Decodes and validates `content` under `rules`.
    fn decode_content(content: &'a [u8], rules: Rules) -> Result<Self, ValueError>;

    /// The number of content octets [`encode_content`](ContentCodec::encode_content) writes.
    fn content_len(&self) -> usize;

    /// Writes the contents in DER and returns the number of bytes written.
    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error>;

    /// For types whose value borrows nothing: the longest contents a BER constructed
    /// encoding may be copied into (at most 32). `0` means a constructed encoding is
    /// [`ErrorKind::ConstructedNotAllowed`](crate::ErrorKind::ConstructedNotAllowed).
    const MAX_COPY_LEN: usize = 0;

    /// Decodes from the copy of a constructed encoding's segments.
    fn decode_from_copy(content: &[u8], rules: Rules) -> Result<Self, ValueError> {
        let _ = (content, rules);
        Err(ValueError::InvalidLength)
    }
}

/// Validates `content` as the universal primitive `tag` under `rules`; tags without a
/// validated primitive pass.
pub(crate) fn validate_content(
    tag: crate::Tag,
    content: &[u8],
    rules: Rules,
) -> Result<(), ValueError> {
    if tag.class != crate::Class::Universal {
        return Ok(());
    }
    match tag.number {
        1 => bool::decode_content(content, rules).map(drop),
        2 => Int::decode_content(content, rules).map(drop),
        10 => Enumerated::decode_content(content, rules).map(drop),
        5 => Null::decode_content(content, rules).map(drop),
        6 => Oid::decode_content(content, rules).map(drop),
        13 => RelOid::decode_content(content, rules).map(drop),
        23 => UtcTime::decode_content(content, rules).map(drop),
        24 => GeneralizedTime::decode_content(content, rules).map(drop),
        _ => Ok(()),
    }
}

macro_rules! fixed_tag {
    ($t:ty, $tag:expr) => {
        impl $crate::FixedTag for $t {
            const TAG: $crate::Tag = $tag;
            const CONSTRUCTED: bool = false;
        }
    };
}
pub(crate) use fixed_tag;
