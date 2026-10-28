//! Wrapper and open types.

use crate::util::{head, saturating_to_u64, tail};
use crate::{
    Class, Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, FixedTag, Header,
    Identifier, Length, MatchTag, Oid, SliceReader, Tag, Writer, header_len,
};

/// One raw TLV: the decoded form of open types such as AlgorithmIdentifier parameters,
/// extension values and attribute values.
///
/// Encoding writes the identifier, the minimal definite length of the contents, and the
/// contents.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Any<'a> {
    header: Header<'a>,
    raw: &'a [u8],
}

impl<'a> Any<'a> {
    pub(crate) fn new(header: Header<'a>, raw: &'a [u8]) -> Self {
        Any { header, raw }
    }

    /// The tag.
    pub const fn tag(&self) -> Tag {
        self.header.tag()
    }

    /// Whether the encoding is constructed.
    pub const fn constructed(&self) -> bool {
        self.header.constructed()
    }

    /// The contents, without header or end-of-contents octets.
    pub fn contents(&self) -> &'a [u8] {
        // The contents follow the header; an indefinite length also ends in the two
        // end-of-contents octets, which aren't part of them.
        let body = tail(self.raw, self.header.raw().len());
        match self.header.length() {
            Length::Definite(_) => body,
            Length::Indefinite => head(body, body.len().saturating_sub(2)),
        }
    }

    /// The whole encoding: header plus contents.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The header.
    pub const fn header(&self) -> &Header<'a> {
        &self.header
    }

    /// A reader over the contents, with the given configuration.
    pub fn contents_reader(&self, config: &crate::Config) -> SliceReader<'a> {
        SliceReader::with_base(self.contents(), self.header.content_offset(), config)
    }
}

impl<'a> Decode<'a> for Any<'a> {
    fn decode(r: &mut SliceReader<'a>) -> Result<Self, Error> {
        r.read_any()
    }
}

impl MatchTag for Any<'_> {
    fn matches_tag(_tag: Tag) -> bool {
        true
    }
}

impl Encode for Any<'_> {
    fn encoded_len(&self) -> Result<u64, Error> {
        let len = saturating_to_u64(self.contents().len());
        Ok(header_len(self.tag(), self.constructed(), len).saturating_add(len))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let contents = self.contents();
        w.write_header(self.header.id(), saturating_to_u64(contents.len()))?;
        w.write_bytes(contents)
    }
}

/// An EXPLICIT context-specific tag `[N]` around `T`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Explicit<const N: u32, T>(pub T);

impl<const N: u32, T> FixedTag for Explicit<N, T> {
    const TAG: Tag = Tag { class: Class::ContextSpecific, number: N };
    const CONSTRUCTED: bool = true;
}

impl<'a, const N: u32, T: Decode<'a>> DecodeValue<'a> for Explicit<N, T> {
    fn decode_value(header: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
        if !header.constructed() {
            return Err(Error::new(ErrorKind::WrongUniversalForm, header.offset()));
        }
        contents.read::<T>().map(Explicit)
    }
}

impl<const N: u32, T: Encode> EncodeValue for Explicit<N, T> {
    fn value_len(&self) -> Result<u64, Error> {
        self.0.encoded_len()
    }

    fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl<const N: u32, T: Encode> Explicit<N, T> {
    /// The encoded length of `inner` wrapped in `[N]`, without constructing the wrapper.
    pub fn encoded_len_of(inner: &T) -> Result<u64, Error> {
        let len = inner.encoded_len()?;
        Ok(header_len(Self::TAG, true, len).saturating_add(len))
    }

    /// Writes `inner` wrapped in `[N]`, without constructing the wrapper.
    pub fn encode_of(inner: &T, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_header(Identifier { tag: Self::TAG, constructed: true }, inner.encoded_len()?)?;
        inner.encode(w)
    }
}

/// An IMPLICIT context-specific tag `[N]` replacing `T`'s tag.
///
/// `T` must be a type with contents of its own: a CHOICE or [`Any`] can't be tagged
/// implicitly, and trying to is a compile error.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Implicit<const N: u32, T>(pub T);

impl<const N: u32, T: FixedTag> FixedTag for Implicit<N, T> {
    const TAG: Tag = Tag { class: Class::ContextSpecific, number: N };
    const CONSTRUCTED: bool = T::CONSTRUCTED;
}

impl<'a, const N: u32, T: DecodeValue<'a>> DecodeValue<'a> for Implicit<N, T> {
    fn decode_value(header: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
        T::decode_value(header, contents).map(Implicit)
    }
}

impl<const N: u32, T: EncodeValue> EncodeValue for Implicit<N, T> {
    fn value_len(&self) -> Result<u64, Error> {
        self.0.value_len()
    }

    fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.0.encode_value(w)
    }
}

impl<const N: u32, T: FixedTag + EncodeValue> Implicit<N, T> {
    /// The encoded length of `inner` retagged `[N]`, without constructing the wrapper.
    pub fn encoded_len_of(inner: &T) -> Result<u64, Error> {
        let len = inner.value_len()?;
        Ok(header_len(Self::TAG, T::CONSTRUCTED, len).saturating_add(len))
    }

    /// Writes `inner` retagged `[N]`, without constructing the wrapper.
    pub fn encode_of(inner: &T, w: &mut Writer<'_>) -> Result<(), Error> {
        let id = Identifier {
            tag: Tag { class: Class::ContextSpecific, number: N },
            constructed: T::CONSTRUCTED,
        };
        w.write_header(id, inner.value_len()?)?;
        inner.encode_value(w)
    }
}

/// A decoded value together with the exact bytes it was decoded from, for anything signed or
/// hashed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WithRaw<'a, T> {
    /// The decoded value.
    pub value: T,
    /// Its exact encoding.
    pub raw: &'a [u8],
}

impl<'a, T: Decode<'a>> Decode<'a> for WithRaw<'a, T> {
    fn decode(r: &mut SliceReader<'a>) -> Result<Self, Error> {
        let (raw, value) = r.read_with_raw(|r| r.read::<T>())?;
        Ok(WithRaw { value, raw })
    }
}

impl<T: MatchTag> MatchTag for WithRaw<'_, T> {
    fn matches_tag(tag: Tag) -> bool {
        T::matches_tag(tag)
    }
}

impl<T: Encode> Encode for WithRaw<'_, T> {
    fn encoded_len(&self) -> Result<u64, Error> {
        self.value.encoded_len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.value.encode(w)
    }
}

/// The unknown trailing components of an extensible SEQUENCE, as a lazy iterator of [`Any`].
///
/// Encoding writes every component back in turn.
#[derive(Clone, Debug)]
pub struct Unknown<'a> {
    reader: SliceReader<'a>,
}

impl<'a> Unknown<'a> {
    pub(crate) fn new(reader: SliceReader<'a>) -> Self {
        Unknown { reader }
    }

    /// Whether there are no unknown components.
    pub fn is_empty(&self) -> bool {
        self.reader.is_empty()
    }

    /// The components, in order.
    pub fn iter(&self) -> UnknownIter<'a> {
        UnknownIter { reader: self.reader.clone() }
    }
}

impl<'a> IntoIterator for &Unknown<'a> {
    type Item = Result<Any<'a>, Error>;
    type IntoIter = UnknownIter<'a>;

    fn into_iter(self) -> UnknownIter<'a> {
        self.iter()
    }
}

/// Iterator over the components of an [`Unknown`].
#[derive(Clone, Debug)]
pub struct UnknownIter<'a> {
    reader: SliceReader<'a>,
}

impl<'a> Iterator for UnknownIter<'a> {
    type Item = Result<Any<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        let item = self.reader.read::<Any<'a>>();
        if item.is_err() {
            self.reader = SliceReader::new(&[], self.reader.config());
        }
        Some(item)
    }
}

impl Encode for Unknown<'_> {
    fn encoded_len(&self) -> Result<u64, Error> {
        self.iter().try_fold(0u64, |sum, any| Ok(sum.saturating_add(any?.encoded_len()?)))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.iter().try_for_each(|any| any?.encode(w))
    }
}

/// A nested DER value of `T` inside an OCTET STRING, decoded under the same configuration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Containing<'a, T> {
    value: T,
    raw: &'a [u8],
}

impl<'a, T> Containing<'a, T> {
    /// Wraps an already-built value; `raw` is not used when encoding.
    pub const fn new(value: T, raw: &'a [u8]) -> Self {
        Containing { value, raw }
    }

    /// The decoded value.
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// The bytes of the nested encoding.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

impl<T> FixedTag for Containing<'_, T> {
    const TAG: Tag = Tag::OCTET_STRING;
    const CONSTRUCTED: bool = false;
}

impl<'a, T: Decode<'a>> DecodeValue<'a> for Containing<'a, T> {
    fn decode_value(header: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
        if header.constructed() {
            return Err(Error::new(ErrorKind::ConstructedNotAllowed, header.offset()));
        }
        let offset = contents.offset();
        let raw = contents.read_contents()?;
        let mut inner = SliceReader::with_base(raw, offset, contents.config());
        let value = inner.read::<T>()?;
        inner.finish()?;
        Ok(Containing { value, raw })
    }
}

impl<T: Encode> EncodeValue for Containing<'_, T> {
    fn value_len(&self) -> Result<u64, Error> {
        self.value.encoded_len()
    }

    fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.value.encode(w)
    }
}

/// Maps an OID to a decoder for open-type parameters.
pub trait DefinedBySet: Sized {
    /// Decodes `value` as the type `id` defines; `Ok(None)` for an unknown OID, in which case
    /// the value stays available as [`Any`].
    fn decode_defined<'a>(id: &Oid<'_>, value: Any<'a>) -> Result<Option<Self>, Error>;
}

/// The tags a type can start with, when they are known at compile time.
///
/// The derive uses this to reject ambiguous SEQUENCE, SET and CHOICE definitions at compile
/// time. An empty list means the tags are unknown, as for [`Any`].
pub trait StaticTags {
    /// The tags.
    const TAGS: TagList;
}

impl<T: FixedTag> StaticTags for T {
    const TAGS: TagList = TagList::EMPTY.with(T::TAG);
}

impl StaticTags for Any<'_> {
    const TAGS: TagList = TagList::EMPTY;
}

/// A fixed-capacity list of tags, built in `const` contexts.
#[derive(Clone, Debug)]
pub struct TagList {
    tags: [Tag; TagList::CAPACITY],
    len: usize,
}

impl TagList {
    /// The most tags a list holds.
    pub const CAPACITY: usize = 64;

    /// The empty list.
    pub const EMPTY: TagList = TagList { tags: [Tag::EOC; TagList::CAPACITY], len: 0 };

    /// This list plus `tag`.
    #[allow(clippy::panic, clippy::indexing_slicing)]
    pub const fn with(mut self, tag: Tag) -> Self {
        if self.len == Self::CAPACITY {
            panic!("too many alternative tags");
        }
        self.tags[self.len] = tag;
        self.len += 1;
        self
    }

    /// This list followed by `other`.
    pub const fn extend(mut self, other: &TagList) -> Self {
        let mut i = 0;
        while i < other.len {
            #[allow(clippy::indexing_slicing)]
            {
                self = self.with(other.tags[i]);
            }
            i += 1;
        }
        self
    }

    /// The first tag, or the end-of-contents tag if the list is empty.
    #[allow(clippy::indexing_slicing)]
    pub const fn first(&self) -> Tag {
        if self.len == 0 { Tag::EOC } else { self.tags[0] }
    }

    /// The number of tags.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the list is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `tag` is in the list.
    #[allow(clippy::indexing_slicing)]
    pub const fn contains(&self, tag: &Tag) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.tags[i].const_eq(tag) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Whether no tag appears in two of `lists`.
    #[allow(clippy::indexing_slicing)]
    pub const fn all_distinct(lists: &[&TagList]) -> bool {
        let mut a = 0;
        while a < lists.len() {
            let mut i = 0;
            while i < lists[a].len {
                let tag = lists[a].tags[i];
                let mut j = i + 1;
                while j < lists[a].len {
                    if lists[a].tags[j].const_eq(&tag) {
                        return false;
                    }
                    j += 1;
                }
                let mut b = a + 1;
                while b < lists.len() {
                    if lists[b].contains(&tag) {
                        return false;
                    }
                    b += 1;
                }
                i += 1;
            }
            a += 1;
        }
        true
    }
}

/// Collects the present components of a SET and yields them in DER order: ascending by tag.
///
/// Support for derived code.
#[derive(Clone, Debug)]
pub struct SetOrder<const N: usize> {
    items: [(Tag, usize); N],
    len: usize,
}

impl<const N: usize> Default for SetOrder<N> {
    fn default() -> Self {
        SetOrder { items: [(Tag::EOC, 0); N], len: 0 }
    }
}

impl<const N: usize> SetOrder<N> {
    /// An empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that component `index` is present with `tag`.
    pub fn push(&mut self, tag: Tag, index: usize) {
        if let Some(slot) = self.items.get_mut(self.len) {
            *slot = (tag, index);
            self.len += 1;
        }
    }

    /// The recorded components, sorted by tag.
    pub fn sorted(&mut self) -> &[(Tag, usize)] {
        let used = self.items.get_mut(..self.len).unwrap_or_default();
        used.sort_unstable_by_key(|item| item.0);
        used
    }
}
