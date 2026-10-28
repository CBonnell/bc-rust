//! A `no_std`, no-alloc ASN.1 BER and DER library built on a sans-io pull tokenizer.
//!
//! Its first consumers are X.509 and CMS, including streaming verification of large CRLs and
//! signed firmware on embedded devices.
//!
//! # Layers
//!
//! - **Foundations**: [`Error`], [`Config`], [`Rules`].
//! - **Codecs** ([`base128`], [`Identifier`], [`Length`], [`Header`]): pure functions over
//!   slices that every other layer shares.
//! - **Tokenizer** ([`Tokenizer`], [`EventSource`]): a sans-io stream of
//!   header/content/end events in constant memory.
//! - **Filters** ([`ContentValidator`], [`StringReassembler`]): optional event transformers.
//! - **Primitives** ([`Int`], [`Oid`], [`BitString`], …): one type per universal primitive.
//! - **Typed decoding** ([`SliceReader`], [`Decode`], [`Encode`]): zero-copy decoding from a
//!   complete buffer.
//! - **Encoding** ([`Writer`], [`encode_to_slice`], [`StreamEncoder`]): two-pass DER encoding.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_asn1::{Config, SliceReader, Oid, Null};
//!
//! // AlgorithmIdentifier { sha256WithRSAEncryption, NULL }
//! let der = [
//!     0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
//! ];
//! let mut reader = SliceReader::new(&der, &Config::DER);
//! let (oid, _params) = reader.read_sequence(|seq| {
//!     let oid: Oid = seq.read()?;
//!     let params: Null = seq.read()?;
//!     Ok((oid, params))
//! })?;
//! reader.finish()?;
//! assert_eq!(oid.to_string(), "1.2.840.113549.1.1.11");
//! # Ok::<(), bouncycastle_asn1::Error>(())
//! ```
//!
//! # Security Considerations
//!
//! Strict DER is the default. Every limit ([`Config::with_max_value_len`],
//! [`Config::with_max_tag_number`], the tokenizer's `DEPTH`) bounds what hostile input can
//! make the parser do; raise them only for a known schema. Nothing panics, nothing allocates
//! in the core, and decoding never sorts or re-encodes.
//!
//! # Memory Usage
//!
//! Everything lives on the stack; nothing allocates. Sizes on a 64-bit target:
//!
//! | Type | Bytes |
//! | --- | --- |
//! | `Tokenizer<8>` / `Tokenizer<32>` / `Tokenizer<64>` | 432 / 1 392 / 2 672 |
//! | `ContentValidator<Tokenizer<32>>` | 1 568 |
//! | `StringReassembler<ContentValidator<Tokenizer<32>>>` | 1 624 |
//! | `StreamEncoder<32>` | 784 |
//! | `SliceReader` | 72 |
//! | `Header` | 56 |
//! | `Config` | 16 |
//! | `Error` | 24 |
//!
//! Reading an indefinite-length value or a constructed time with a `SliceReader` briefly uses
//! one `Tokenizer<32>` on the stack. A `const` constraint is an [`IntervalSet`] of 1 040 bytes
//! in the binary's read-only data, not on the stack.
//!
//! # Features
//!
//! `alloc` adds `Vec`-backed conveniences, `heapless` adds bounded collections, `ber-time`
//! enables the full BER time grammar, and `derive` re-exports the derive macros.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod collections;
mod config;
mod constraint;
mod error;
mod filters;
mod header;
mod identifier;
mod length;
mod primitives;
mod reader;
mod stream_encoder;
mod tokenizer;
mod traits;
mod types;
mod util;
mod writer;

pub mod base128;

pub use collections::{
    SequenceOf, SequenceOfIter, SequenceOfRef, SetOf, SetOfIter, SetOfRef, sort_der_set_of,
};
pub use config::{Config, Deviations, Rules, Tolerance, Tolerances, ValueCount};
pub use constraint::{
    AlphabetConstrainable, IntervalSet, MAX_INTERVALS, RangeConstrainable, SizeConstrainable,
    check_alphabet, check_range, check_size,
};
pub use error::{Error, ErrorKind, ValueError};
pub use filters::{ContentValidator, StringReassembler};
pub use header::{Header, HeaderParse};
pub use identifier::{Class, Identifier, Tag};
pub use length::Length;
pub use primitives::{
    Arcs, BitString, BmpString, ContentCodec, Enumerated, GeneralizedTime, Ia5String, Int,
    NamedBits, Null, NumericString, OctetString, Oid, PrintableString, RelOid, TeletexString,
    UniversalString, UtcTime, Utf8String, VisibleString, days_in_month,
};
pub use reader::SliceReader;
pub use stream_encoder::StreamEncoder;
pub use tokenizer::{Event, EventSource, Step, StepKind, Tokenizer};
pub use traits::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, MatchTag, header_len};
pub use types::{
    Any, Containing, DefinedBySet, Explicit, Implicit, SetOrder, StaticTags, TagList, Unknown,
    UnknownIter, WithRaw,
};
pub use writer::{Writer, encode_to_slice};

pub use base128::Base128Int;

#[cfg(feature = "derive")]
pub use bouncycastle_asn1_derive::{Asn1, oid};
