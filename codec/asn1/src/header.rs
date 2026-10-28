//! The combined identifier and length octets.

use crate::util::{head, saturating_to_u64, tail};
use crate::{Class, Config, Error, ErrorKind, Identifier, Length, Rules, Tag};

/// A decoded header: identifier octets and length octets, at most 15 bytes.
///
/// Only [`Header::decode`] constructs one, so [`raw`](Header::raw) always agrees with
/// [`id`](Header::id), [`length`](Header::length) and [`offset`](Header::offset).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header<'a> {
    id: Identifier,
    length: Length,
    offset: u64,
    raw: &'a [u8],
}

/// The result of [`Header::decode`] on input that may be cut short.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HeaderParse<'a> {
    /// The header was complete.
    Complete(Header<'a>),
    /// The input ended inside the header; it must hold at least `at_least` bytes in total.
    Incomplete {
        /// The minimum input length that lets decoding make progress.
        at_least: usize,
    },
}

fn fixed_form(tag: Tag) -> Option<bool> {
    if tag.class != Class::Universal {
        return None;
    }
    match tag.number {
        16 | 17 => Some(true),
        1 | 2 | 5 | 6 | 10 | 13 => Some(false),
        _ => None,
    }
}

pub(crate) fn is_string_type(tag: Tag) -> bool {
    tag.class == Class::Universal && matches!(tag.number, 3 | 4 | 7 | 12 | 18..=30)
}

impl<'a> Header<'a> {
    /// Decodes a header from the start of `input`.
    ///
    /// `base` is the absolute position of `input[0]`; error offsets are absolute. `rules` are
    /// the rules active for this value, which may be stricter than `config.rules()`.
    ///
    /// Applies every header-level check: indefinite length on a primitive, a length above
    /// `config.max_value_len()`, a wrong primitive/constructed form for a universal type with
    /// a fixed form, and constructed string types under DER.
    ///
    /// # Errors
    ///
    /// Any of the identifier and length errors, plus [`ErrorKind::IndefiniteOnPrimitive`],
    /// [`ErrorKind::ElementTooLarge`], [`ErrorKind::WrongUniversalForm`] and
    /// [`ErrorKind::ConstructedNotAllowed`].
    pub fn decode(
        input: &'a [u8],
        base: u64,
        config: &Config,
        rules: Rules,
    ) -> Result<HeaderParse<'a>, Error> {
        let (id, id_len) = match Identifier::decode(input, config, rules) {
            Ok(v) => v,
            Err(e) if *e.kind() == ErrorKind::Truncated => {
                return Ok(HeaderParse::Incomplete { at_least: input.len() + 1 });
            }
            Err(e) => return Err(e.shifted(base)),
        };
        if let Some(constructed) = fixed_form(id.tag)
            && constructed != id.constructed
        {
            return Err(Error::new(ErrorKind::WrongUniversalForm, base));
        }
        if rules == Rules::Der && id.constructed && is_string_type(id.tag) {
            return Err(Error::new(ErrorKind::ConstructedNotAllowed, base));
        }
        let length_at = base.saturating_add(saturating_to_u64(id_len));
        let rest = tail(input, id_len);
        let Some(&first) = rest.first() else {
            return Ok(HeaderParse::Incomplete { at_least: id_len + 1 });
        };
        if first > 0x80 && first != 0xFF {
            let needed = id_len + 1 + usize::from(first & 0x7F);
            if input.len() < needed {
                return Ok(HeaderParse::Incomplete { at_least: needed });
            }
        }
        let (length, length_len) = Length::decode(rest, rules).map_err(|e| e.shifted(length_at))?;
        match length {
            Length::Indefinite if !id.constructed => {
                return Err(Error::new(ErrorKind::IndefiniteOnPrimitive, length_at));
            }
            Length::Definite(len) if len > config.max_value_len() => {
                return Err(Error::new(ErrorKind::ElementTooLarge, length_at));
            }
            _ => {}
        }
        Ok(HeaderParse::Complete(Header {
            id,
            length,
            offset: base,
            raw: head(input, id_len + length_len),
        }))
    }

    /// The identifier octets.
    pub const fn id(&self) -> Identifier {
        self.id
    }

    /// The tag.
    pub const fn tag(&self) -> Tag {
        self.id.tag
    }

    /// Whether the encoding is constructed.
    pub const fn constructed(&self) -> bool {
        self.id.constructed
    }

    /// The length. This is [`Length`], not a byte count.
    pub const fn length(&self) -> Length {
        self.length
    }

    /// The absolute position of the header's first byte.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// The absolute position of the first content byte.
    pub const fn content_offset(&self) -> u64 {
        self.offset.saturating_add(self.raw.len() as u64)
    }

    /// Exactly the identifier and length octets.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The header of a string that has been reassembled into one primitive value.
    pub(crate) fn into_primitive(mut self) -> Self {
        self.id.constructed = false;
        self
    }
}
