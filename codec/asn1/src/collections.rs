//! SEQUENCE OF, SET OF and DER set ordering.

use core::marker::PhantomData;

use crate::util::{insufficient, saturating_to_u64};
use crate::{
    Decode, DecodeValue, Deviations, Encode, EncodeValue, Error, ErrorKind, FixedTag, Header,
    SizeConstrainable, SliceReader, Tag, Tolerance, Writer,
};

fn count_elements<'a>(
    contents: &mut SliceReader<'a>,
    mut each: impl FnMut(&mut SliceReader<'a>, &'a [u8], u64) -> Result<(), Error>,
) -> Result<usize, Error> {
    let mut len = 0;
    while !contents.is_empty() {
        let at = contents.offset();
        let (raw, ()) = contents.read_with_raw(|r| r.read::<crate::Any<'a>>().map(drop))?;
        each(contents, raw, at)?;
        len += 1;
    }
    Ok(len)
}

macro_rules! lazy_collection {
    ($name:ident, $iter:ident, $tag:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug)]
        pub struct $name<'a, T> {
            reader: SliceReader<'a>,
            len: usize,
            marker: PhantomData<fn() -> T>,
        }

        impl<'a, T> $name<'a, T> {
            /// The number of elements.
            pub const fn len(&self) -> usize {
                self.len
            }

            /// Whether there are no elements.
            pub const fn is_empty(&self) -> bool {
                self.len == 0
            }
        }

        impl<'a, T: Decode<'a>> $name<'a, T> {
            /// The elements, each decoded as `T` when reached.
            pub fn iter(&self) -> $iter<'a, T> {
                $iter { reader: self.reader.clone(), marker: PhantomData }
            }
        }

        impl<'a, T: Decode<'a>> IntoIterator for &$name<'a, T> {
            type Item = Result<T, Error>;
            type IntoIter = $iter<'a, T>;

            fn into_iter(self) -> $iter<'a, T> {
                self.iter()
            }
        }

        /// Iterator over the elements of the collection.
        #[derive(Clone, Debug)]
        pub struct $iter<'a, T> {
            reader: SliceReader<'a>,
            marker: PhantomData<fn() -> T>,
        }

        impl<'a, T> $iter<'a, T> {
            /// The tolerances used by the elements decoded so far.
            pub fn deviations(&self) -> &Deviations {
                self.reader.deviations()
            }
        }

        impl<'a, T: Decode<'a>> Iterator for $iter<'a, T> {
            type Item = Result<T, Error>;

            fn next(&mut self) -> Option<Self::Item> {
                if self.reader.is_empty() {
                    return None;
                }
                let item = self.reader.read::<T>();
                if item.is_err() {
                    self.reader = SliceReader::new(&[], self.reader.config());
                }
                Some(item)
            }
        }

        impl<T> FixedTag for $name<'_, T> {
            const TAG: Tag = $tag;
            const CONSTRUCTED: bool = true;
        }

        impl<T> SizeConstrainable for $name<'_, T> {
            fn constraint_size(&self) -> u64 {
                saturating_to_u64(self.len)
            }
        }

        impl<'a, T: Decode<'a> + Encode> EncodeValue for $name<'a, T> {
            fn value_len(&self) -> Result<u64, Error> {
                self.iter().try_fold(0u64, |sum, item| Ok(sum.saturating_add(item?.encoded_len()?)))
            }

            fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
                let mut items = self.iter();
                encode_elements(w, Self::ORDERED, |w| match items.next() {
                    Some(item) => item?.encode(w).map(|()| true),
                    None => Ok(false),
                })
            }
        }
    };
}

lazy_collection!(
    SequenceOf,
    SequenceOfIter,
    Tag::SEQUENCE,
    "A borrowed SEQUENCE OF.\n\nDecoding validates every element's TLV structure up front; iteration decodes each element as `T`."
);
lazy_collection!(
    SetOf,
    SetOfIter,
    Tag::SET,
    "A borrowed SET OF.\n\nDecoding validates every element's TLV structure up front and, under DER, that the elements are in ascending order of their encodings ([`ErrorKind::SetOfNotSorted`] unless `Tolerance::UnsortedSetOf` is enabled for the field). It never sorts or re-encodes."
);

impl<T> SequenceOf<'_, T> {
    const ORDERED: bool = false;
}

impl<T> SetOf<'_, T> {
    const ORDERED: bool = true;
}

impl<'a, T: Decode<'a>> DecodeValue<'a> for SequenceOf<'a, T> {
    fn decode_value(_: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
        let reader = contents.clone();
        let len = count_elements(contents, |_, _, _| Ok(()))?;
        Ok(SequenceOf { reader, len, marker: PhantomData })
    }
}

impl<'a, T: Decode<'a>> DecodeValue<'a> for SetOf<'a, T> {
    fn decode_value(_: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
        let reader = contents.clone();
        let mut previous: Option<&'a [u8]> = None;
        let len = count_elements(contents, |contents, raw, at| {
            if contents.rules() == crate::Rules::Der && previous.is_some_and(|p| p > raw) {
                if !contents.tolerates(Tolerance::UnsortedSetOf) {
                    return Err(Error::new(ErrorKind::SetOfNotSorted, at));
                }
                contents.record_deviation(Tolerance::UnsortedSetOf);
            }
            previous = Some(raw);
            Ok(())
        })?;
        Ok(SetOf { reader, len, marker: PhantomData })
    }
}

/// Writes the elements `next` produces; with `ordered`, fails with
/// [`ErrorKind::SetOfNotSorted`] unless their encodings are in ascending order.
fn encode_elements(
    w: &mut Writer<'_>,
    ordered: bool,
    mut next: impl FnMut(&mut Writer<'_>) -> Result<bool, Error>,
) -> Result<(), Error> {
    let mut previous: Option<(usize, usize)> = None;
    loop {
        let start = w.position();
        if !next(w)? {
            return Ok(());
        }
        let end = w.position();
        if ordered {
            if let Some((p_start, p_end)) = previous {
                let written = w.written();
                if written.get(p_start..p_end) > written.get(start..end) {
                    return Err(Error::new(ErrorKind::SetOfNotSorted, saturating_to_u64(start)));
                }
            }
            previous = Some((start, end));
        }
    }
}

macro_rules! slice_collection {
    ($name:ident, $tag:expr, $ordered:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug)]
        pub struct $name<'s, T>(pub &'s [T]);

        impl<T> FixedTag for $name<'_, T> {
            const TAG: Tag = $tag;
            const CONSTRUCTED: bool = true;
        }

        impl<T> SizeConstrainable for $name<'_, T> {
            fn constraint_size(&self) -> u64 {
                saturating_to_u64(self.0.len())
            }
        }

        impl<T: Encode> EncodeValue for $name<'_, T> {
            fn value_len(&self) -> Result<u64, Error> {
                self.0
                    .iter()
                    .try_fold(0u64, |sum, item| Ok(sum.saturating_add(item.encoded_len()?)))
            }

            fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
                let mut items = self.0.iter();
                encode_elements(w, $ordered, |w| match items.next() {
                    Some(item) => item.encode(w).map(|()| true),
                    None => Ok(false),
                })
            }
        }
    };
}

slice_collection!(
    SequenceOfRef,
    Tag::SEQUENCE,
    false,
    "Encodes a slice as a SEQUENCE OF, in the given order."
);
slice_collection!(
    SetOfRef,
    Tag::SET,
    true,
    "Encodes a slice as a SET OF in the given order.\n\nFails with [`ErrorKind::SetOfNotSorted`] if the encodings aren't in DER order; sort first with [`sort_der_set_of`]."
);

/// Sorts `items` into DER SET OF order, the ascending order of their encodings, without
/// allocating.
///
/// `scratch` must hold the two largest encodings among `items` at once; the comparison
/// encodes both operands into it.
///
/// # Errors
///
/// [`ErrorKind::InsufficientSize`] if `scratch` is too small (nothing is sorted), and
/// whatever an item's encoder reports.
pub fn sort_der_set_of<T: Encode>(items: &mut [T], scratch: &mut [u8]) -> Result<(), Error> {
    let mut largest = 0usize;
    for item in items.iter() {
        let len = usize::try_from(item.encoded_len()?).map_err(|_| insufficient(usize::MAX, 0))?;
        largest = largest.max(len);
    }
    let required = largest.saturating_mul(2);
    if scratch.len() < required {
        return Err(insufficient(required, 0));
    }
    let (first, second) = scratch.split_at_mut(largest);
    items.sort_unstable_by(|a, b| {
        let a = encode_into(a, first);
        let b = encode_into(b, second);
        a.cmp(b)
    });
    Ok(())
}

fn encode_into<'b, T: Encode>(item: &T, buf: &'b mut [u8]) -> &'b [u8] {
    match crate::encode_to_slice(item, buf) {
        Ok(encoded) => encoded,
        Err(_) => &[],
    }
}

#[cfg(feature = "alloc")]
mod alloc_impls {
    use alloc::vec::Vec;

    use super::*;

    impl<T> FixedTag for Vec<T> {
        const TAG: Tag = Tag::SEQUENCE;
        const CONSTRUCTED: bool = true;
    }

    impl<'a, T: Decode<'a>> DecodeValue<'a> for Vec<T> {
        fn decode_value(_: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
            let mut items = Vec::new();
            while !contents.is_empty() {
                items.push(contents.read::<T>()?);
            }
            Ok(items)
        }
    }

    impl<T: Encode> EncodeValue for Vec<T> {
        fn value_len(&self) -> Result<u64, Error> {
            SequenceOfRef(self.as_slice()).value_len()
        }

        fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
            SequenceOfRef(self.as_slice()).encode_value(w)
        }
    }

    impl<T> SizeConstrainable for Vec<T> {
        fn constraint_size(&self) -> u64 {
            saturating_to_u64(self.len())
        }
    }
}

#[cfg(feature = "heapless")]
mod heapless_impls {
    use super::*;

    impl<T, const N: usize> FixedTag for heapless::Vec<T, N> {
        const TAG: Tag = Tag::SEQUENCE;
        const CONSTRUCTED: bool = true;
    }

    impl<'a, T: Decode<'a>, const N: usize> DecodeValue<'a> for heapless::Vec<T, N> {
        fn decode_value(_: &Header<'a>, contents: &mut SliceReader<'a>) -> Result<Self, Error> {
            let mut items = heapless::Vec::new();
            while !contents.is_empty() {
                let at = contents.offset();
                let item = contents.read::<T>()?;
                items.push(item).map_err(|_| Error::new(ErrorKind::CapacityExceeded, at))?;
            }
            Ok(items)
        }
    }

    impl<T: Encode, const N: usize> EncodeValue for heapless::Vec<T, N> {
        fn value_len(&self) -> Result<u64, Error> {
            SequenceOfRef(self.as_slice()).value_len()
        }

        fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
            SequenceOfRef(self.as_slice()).encode_value(w)
        }
    }

    impl<T, const N: usize> SizeConstrainable for heapless::Vec<T, N> {
        fn constraint_size(&self) -> u64 {
            saturating_to_u64(self.len())
        }
    }
}
