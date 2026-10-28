//! The typed decoding and encoding traits.

use crate::util::saturating_to_u64;
use crate::{ContentCodec, Error, ErrorKind, Header, Identifier, Length, SliceReader, Tag, Writer};

/// A type with one statically known tag.
pub trait FixedTag {
    /// The tag.
    const TAG: Tag;
    /// Whether the encoding is constructed.
    const CONSTRUCTED: bool;
}

/// Decides, from a tag alone, whether a type would decode a value; used for OPTIONAL, DEFAULT
/// and CHOICE dispatch.
pub trait MatchTag {
    /// Whether a value tagged `tag` can be decoded as this type.
    fn matches_tag(tag: Tag) -> bool;
}

/// Decodes a value from its contents only, which enables IMPLICIT tagging.
pub trait DecodeValue<'a>: Sized {
    /// Decodes from `contents`, a reader over exactly the contents of the value whose header
    /// is `header`. It shares the parent's configuration and deviation record.
    fn decode_value(header: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error>;
}

/// Decodes a whole TLV.
pub trait Decode<'a>: Sized {
    /// Reads one value from `r`.
    fn decode(r: &mut SliceReader<'a>) -> Result<Self, Error>;
}

/// Encodes a value's contents only.
pub trait EncodeValue {
    /// The number of content octets.
    fn value_len(&self) -> Result<u64, Error>;
    /// Writes the contents.
    fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error>;
}

/// Encodes a whole TLV as DER.
pub trait Encode {
    /// The total encoded length, header included.
    fn encoded_len(&self) -> Result<u64, Error>;
    /// Writes the TLV.
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error>;
}

impl<'a, T: ContentCodec<'a>> DecodeValue<'a> for T {
    fn decode_value(header: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
        let rules = contents.rules();
        let invalid = |e| Error::value(e, header.content_offset());
        if !header.constructed() {
            let bytes = contents.read_contents()?;
            return T::decode_content(bytes, rules).map_err(invalid);
        }
        if T::MAX_COPY_LEN == 0 {
            return Err(Error::new(ErrorKind::ConstructedNotAllowed, header.offset()));
        }
        let mut copy = [0u8; 32];
        let len = contents.copy_segments(header.tag(), T::MAX_COPY_LEN, &mut copy)?;
        let bytes = copy.get(..len).unwrap_or(&[]);
        T::decode_from_copy(bytes, rules).map_err(invalid)
    }
}

impl<'a, T: ContentCodec<'a>> EncodeValue for T {
    fn value_len(&self) -> Result<u64, Error> {
        Ok(saturating_to_u64(self.content_len()))
    }

    fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let len = self.content_len();
        let dst = w.reserve(len)?;
        let written = self.encode_content(dst)?;
        if written != len {
            return Err(Error::new(ErrorKind::InvalidState, 0));
        }
        Ok(())
    }
}

impl<T: FixedTag> MatchTag for T {
    fn matches_tag(tag: Tag) -> bool {
        tag == T::TAG
    }
}

impl<'a, T: FixedTag + DecodeValue<'a>> Decode<'a> for T {
    fn decode(r: &mut SliceReader<'a>) -> Result<Self, Error> {
        r.read_tlv_with(Some(T::TAG), |header, contents| T::decode_value(header, contents))
    }
}

impl<T: FixedTag + EncodeValue> Encode for T {
    fn encoded_len(&self) -> Result<u64, Error> {
        let len = self.value_len()?;
        Ok(header_len(T::TAG, T::CONSTRUCTED, len).saturating_add(len))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let len = self.value_len()?;
        w.write_header(Identifier { tag: T::TAG, constructed: T::CONSTRUCTED }, len)?;
        let start = w.position();
        self.encode_value(w)?;
        if saturating_to_u64(w.position() - start) != len {
            return Err(Error::new(ErrorKind::InvalidState, saturating_to_u64(w.position())));
        }
        Ok(())
    }
}

/// The length of the header of a TLV with the given tag, form and content length.
pub fn header_len(tag: Tag, constructed: bool, content_len: u64) -> u64 {
    let id = Identifier { tag, constructed };
    saturating_to_u64(id.encoded_len() + Length::Definite(content_len).encoded_len())
}

impl<T: Encode> Encode for Option<T> {
    fn encoded_len(&self) -> Result<u64, Error> {
        self.as_ref().map_or(Ok(0), Encode::encoded_len)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.as_ref().map_or(Ok(()), |v| v.encode(w))
    }
}
