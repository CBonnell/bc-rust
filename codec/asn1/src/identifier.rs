//! Identifier octets.

use crate::util::insufficient;
use crate::{Config, Error, ErrorKind, Rules, base128};

/// The class of a tag, in encoding order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Class {
    /// Universal.
    Universal,
    /// Application.
    Application,
    /// Context-specific.
    ContextSpecific,
    /// Private.
    Private,
}

impl Class {
    const fn bits(self) -> u8 {
        match self {
            Class::Universal => 0x00,
            Class::Application => 0x40,
            Class::ContextSpecific => 0x80,
            Class::Private => 0xC0,
        }
    }

    const fn from_bits(b: u8) -> Self {
        match b >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        }
    }

    const fn rank(self) -> u8 {
        self.bits() >> 6
    }
}

/// A tag: class and number. Ordered by (class, number), ignoring the constructed bit, which
/// is the order DER requires for SET components.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Tag {
    /// The class.
    pub class: Class,
    /// The tag number.
    pub number: u32,
}

macro_rules! universal_tags {
    ($($(#[$m:meta])* $name:ident = $n:expr;)*) => {
        impl Tag {
            $($(#[$m])* pub const $name: Tag = Tag::universal($n);)*
        }
    };
}

universal_tags! {
    /// End-of-contents marker (universal 0).
    EOC = 0;
    /// BOOLEAN.
    BOOLEAN = 1;
    /// INTEGER.
    INTEGER = 2;
    /// BIT STRING.
    BIT_STRING = 3;
    /// OCTET STRING.
    OCTET_STRING = 4;
    /// NULL.
    NULL = 5;
    /// OBJECT IDENTIFIER.
    OBJECT_IDENTIFIER = 6;
    /// ENUMERATED.
    ENUMERATED = 10;
    /// UTF8String.
    UTF8_STRING = 12;
    /// RELATIVE-OID.
    RELATIVE_OID = 13;
    /// SEQUENCE and SEQUENCE OF.
    SEQUENCE = 16;
    /// SET and SET OF.
    SET = 17;
    /// NumericString.
    NUMERIC_STRING = 18;
    /// PrintableString.
    PRINTABLE_STRING = 19;
    /// TeletexString.
    TELETEX_STRING = 20;
    /// IA5String.
    IA5_STRING = 22;
    /// UTCTime.
    UTC_TIME = 23;
    /// GeneralizedTime.
    GENERALIZED_TIME = 24;
    /// VisibleString.
    VISIBLE_STRING = 26;
    /// UniversalString.
    UNIVERSAL_STRING = 28;
    /// BMPString.
    BMP_STRING = 30;
}

impl Tag {
    /// A universal tag.
    pub const fn universal(number: u32) -> Tag {
        Tag { class: Class::Universal, number }
    }

    /// A context-specific tag.
    pub const fn context(number: u32) -> Tag {
        Tag { class: Class::ContextSpecific, number }
    }

    /// Equality usable in `const` contexts.
    pub const fn const_eq(&self, other: &Tag) -> bool {
        self.class.rank() == other.class.rank() && self.number == other.number
    }
}

/// The identifier octets of an encoding (X.690 §8.1.2): the tag plus the primitive/constructed
/// form.
///
/// Not to be confused with an identifier in ASN.1 notation, such as a field name, or with an
/// object identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Identifier {
    /// The tag.
    pub tag: Tag,
    /// Whether the encoding is constructed.
    pub constructed: bool,
}

impl Identifier {
    /// Decodes identifier octets from the start of `input`, returning them and the number of
    /// bytes used. Error offsets are relative to `input`.
    ///
    /// Tag numbers 0 to 30 must use the single-octet form in BER as well as DER.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Truncated`], [`ErrorKind::NonMinimalBase128`],
    /// [`ErrorKind::HighFormForLowTag`] and [`ErrorKind::TagNumberTooLarge`].
    pub fn decode(input: &[u8], config: &Config, _rules: Rules) -> Result<(Self, usize), Error> {
        let (&first, rest) = input.split_first().ok_or(Error::new(ErrorKind::Truncated, 0))?;
        let class = Class::from_bits(first);
        let constructed = first & 0x20 != 0;
        let low = first & 0x1F;
        if low != 0x1F {
            let number = u32::from(low);
            if number > config.max_tag_number() {
                return Err(Error::new(ErrorKind::TagNumberTooLarge, 0));
            }
            return Ok((Identifier { tag: Tag { class, number }, constructed }, 1));
        }
        let (number, used) = match base128::decode::<u32>(rest) {
            Ok(v) => v,
            Err(e) if *e.kind() == ErrorKind::Base128Overflow => {
                return Err(Error::new(ErrorKind::TagNumberTooLarge, 0));
            }
            Err(e) => return Err(e.shifted(1)),
        };
        if number < 31 {
            return Err(Error::new(ErrorKind::HighFormForLowTag, 0));
        }
        if number > config.max_tag_number() {
            return Err(Error::new(ErrorKind::TagNumberTooLarge, 0));
        }
        Ok((Identifier { tag: Tag { class, number }, constructed }, 1 + used))
    }

    /// Encodes the identifier octets and returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InsufficientSize`] if `out` is too small; nothing is written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len();
        let dst = out.get_mut(..len).ok_or_else(|| insufficient(len, 0))?;
        let form = if self.constructed { 0x20 } else { 0 };
        let lead = self.tag.class.bits() | form;
        match dst.split_first_mut() {
            Some((first, _)) if self.tag.number < 31 => *first = lead | self.tag.number as u8,
            Some((first, rest)) => {
                *first = lead | 0x1F;
                base128::encode(self.tag.number, rest)?;
            }
            None => return Err(insufficient(len, 0)),
        }
        Ok(len)
    }

    /// The number of bytes [`encode`](Identifier::encode) writes.
    pub fn encoded_len(&self) -> usize {
        if self.tag.number < 31 { 1 } else { 1 + base128::encoded_len(self.tag.number) }
    }
}
