//! Error types.

use core::fmt;

use crate::Tag;

/// A decoding or encoding failure together with the absolute byte offset it was detected at.
///
/// [`offset`](Error::offset) is the absolute position of the first byte that could not be
/// accepted. When streaming with `eof = false`, running out of input is
/// [`StepKind::NeedMore`](crate::StepKind::NeedMore), never an error.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Error {
    kind: ErrorKind,
    offset: u64,
}

impl Error {
    /// Creates an error of `kind` detected at absolute `offset`.
    pub const fn new(kind: ErrorKind, offset: u64) -> Self {
        Error { kind, offset }
    }

    /// What went wrong.
    pub const fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The absolute position of the first byte that could not be accepted.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub(crate) fn shifted(self, by: u64) -> Self {
        Error { kind: self.kind, offset: self.offset.saturating_add(by) }
    }

    pub(crate) const fn value(error: ValueError, offset: u64) -> Self {
        Error { kind: ErrorKind::InvalidValue(error), offset }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at offset {}", self.kind, self.offset)
    }
}

impl core::error::Error for Error {}

/// The reason an [`Error`] was raised.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ErrorKind {
    /// Input ended (with `eof = true`, or at the end of a complete slice) inside a header, a
    /// value, or an unterminated base-128 number.
    Truncated,
    /// Opening a value when `DEPTH` values are already open.
    DepthExceeded,
    /// A definite length doesn't fit `u64`.
    LengthOverflow,
    /// A length's first octet is `0xFF`.
    ReservedLengthOctet,
    /// A value's length exceeds [`Config::max_value_len`](crate::Config::max_value_len).
    ElementTooLarge,
    /// Under DER, a length uses the long form below 128 or has leading zero octets.
    NonMinimalLength,
    /// A high-form tag number starts with `0x80` (invalid in BER and DER).
    NonMinimalBase128,
    /// A base-128 number doesn't fit the requested integer type.
    Base128Overflow,
    /// A tag number from 0 to 30 uses the high form; invalid under BER and DER.
    HighFormForLowTag,
    /// A tag number exceeds [`Config::max_tag_number`](crate::Config::max_tag_number) or `u32`.
    TagNumberTooLarge,
    /// Indefinite length under DER.
    IndefiniteNotAllowed,
    /// Indefinite length on a primitive value.
    IndefiniteOnPrimitive,
    /// A constructed string encoding under DER, or reaching a typed decoder that needs
    /// contiguous contents.
    ConstructedNotAllowed,
    /// A universal type with a fixed form uses the other one, such as a primitive SEQUENCE or a
    /// constructed INTEGER.
    WrongUniversalForm,
    /// A nested value extends past its enclosing definite-length value.
    ChildOverrunsParent,
    /// A universal tag 0 encoding outside an indefinite-length value.
    UnexpectedEoc,
    /// Typed decoding met a tag the schema doesn't allow there; `expected` is `None` when
    /// several tags would have been accepted.
    UnexpectedTag {
        /// The tag that was required, if exactly one was.
        expected: Option<Tag>,
        /// The tag that was found.
        found: Tag,
    },
    /// A primitive's contents are invalid for its type.
    InvalidValue(ValueError),
    /// Under DER, a field equal to its DEFAULT is encoded, without the tolerance.
    DefaultValueEncoded,
    /// Under DER, SET OF elements aren't in ascending order of their encodings, without the
    /// tolerance; also raised when encoding through [`SetOfRef`](crate::SetOfRef).
    SetOfNotSorted,
    /// `tighten_rules` was given rules looser than the current ones.
    RulesLoosened,
    /// A value breaks a `constraint` attribute or fails a `validate` hook.
    ConstraintViolated,
    /// Valid input has more elements than a fixed-capacity container holds.
    CapacityExceeded,
    /// Bytes remain where none may.
    TrailingData,
    /// An API call in the wrong state.
    InvalidState,
    /// An output buffer is too small; nothing was written.
    InsufficientSize {
        /// The size needed.
        required: usize,
    },
}

/// How a primitive's contents are invalid.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ValueError {
    /// BOOLEAN contents aren't exactly one octet.
    BooleanLength,
    /// Under DER, a BOOLEAN is neither `0x00` nor `0xFF`.
    BooleanNotDer,
    /// INTEGER or ENUMERATED contents are empty.
    IntegerEmpty,
    /// The first nine bits of an INTEGER or ENUMERATED are all zeros or all ones.
    IntegerNotMinimal,
    /// An INTEGER or ENUMERATED doesn't fit its target.
    IntegerOutOfRange,
    /// NULL contents aren't empty.
    NullNotEmpty,
    /// OBJECT IDENTIFIER or RELATIVE-OID contents are empty.
    OidEmpty,
    /// The first OID arcs are not a valid combination.
    OidFirstArc,
    /// An OID or RELATIVE-OID component starts with `0x80`.
    OidNotMinimal,
    /// The last OID or RELATIVE-OID component never ends.
    OidTruncated,
    /// An arc doesn't fit `u128`.
    OidArcTooLarge,
    /// BIT STRING contents are empty, the unused-bits octet exceeds 7, or it is non-zero with
    /// no data octets.
    BitStringUnusedBits,
    /// Under DER, the unused bits of the last octet aren't zero.
    BitStringPaddingNotZero,
    /// Under DER, a named bit list ends with a zero bit.
    NamedBitsTrailingZero,
    /// Bytes that don't decode to characters.
    InvalidCharacterEncoding,
    /// A decoded character outside the type's built-in alphabet.
    NotInAlphabet,
    /// A string's length doesn't fit its encoding.
    InvalidLength,
    /// UTCTime or GeneralizedTime contents are invalid.
    InvalidTime,
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for ValueError {}
