//! Derive macros for `bouncycastle-asn1`.
//!
//! - `#[derive(Asn1)]` turns a struct into a SEQUENCE (or SET with `#[asn1(set)]`) and an enum
//!   into a CHOICE.
//! - `oid!("1.2.840.113549")` produces an `Oid<'static>` at compile time.
//!
//! # Usage Examples
//!
//! ```ignore
//! use bouncycastle_asn1::{Any, Oid, oid};
//! use bouncycastle_asn1_derive::Asn1;
//!
//! #[derive(Asn1)]
//! struct AlgorithmIdentifier<'a> {
//!     algorithm: Oid<'a>,
//!     parameters: Option<Any<'a>>,
//! }
//!
//! const SHA256: Oid<'static> = oid!("2.16.840.1.101.3.4.2.1");
//! ```
//!
//! # Memory Usage
//!
//! The macros run at compile time and add no runtime state. A derived type decodes by reading
//! its fields from a `SliceReader` (72 bytes) and holds borrowed slices of the input.
//!
//! # Security Considerations
//!
//! The generated code is strict: unknown tags, trailing components and encoded DEFAULT values
//! are errors unless the schema declares otherwise, and tag ambiguity is a compile error where
//! tags are static. Use `cargo expand` to review what is generated.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{DeriveInput, Lifetime, parse_macro_input, parse_quote};

mod attrs;
mod choice;
mod constraint;
mod fields;
mod oid;
mod structs;

/// Derives the ASN.1 traits for a struct (SEQUENCE or SET) or an enum (CHOICE).
///
/// A struct implements `FixedTag`, `DecodeValue` and `EncodeValue`, so it also works as an
/// OPTIONAL or DEFAULT field and under `Implicit`. An enum implements `Decode`, `Encode`,
/// `MatchTag` and `StaticTags`. Fields are untagged unless an attribute says otherwise, and an
/// `Option<T>` field is OPTIONAL.
///
/// # Attributes
///
/// | Attribute | On | Meaning |
/// | --- | --- | --- |
/// | `#[asn1(set)]` | struct | Encode as SET instead of SEQUENCE |
/// | `#[asn1(transparent)]` | single-field struct | Encode as the inner type |
/// | `#[asn1(extensible)]` | struct or enum | Unknown trailing components or alternatives are accepted |
/// | `explicit = N` / `implicit = N` | field or variant | Context-specific tag N |
/// | `default = <expr>` | field | DEFAULT value; omitted when encoding equal values |
/// | `constraint = "<X.680 constraint>"` | field or transparent struct | Subtype constraint, repeatable |
/// | `validate = path` | field or type | Custom check, `fn(&T) -> bool` |
/// | `der` | field | Decode this field's subtree under DER rules |
/// | `tolerate(encoded_default)` | field with `default` | Accept an encoded default when `Tolerance::EncodedDefault` is set |
/// | `tolerate(unsorted_set_of)` | `SetOf` field | Accept unsorted DER SET OF when `Tolerance::UnsortedSetOf` is set |
/// | `defined_by = "field", set = Type` | `Any` field | Check the open type through `Type: DefinedBySet` |
///
/// # Compile-time checks
///
/// - In a SEQUENCE, each run of OPTIONAL and DEFAULT fields plus the next field must have
///   distinct tags; in a SET and a CHOICE all tags must be distinct. Untagged `Any` fields
///   can't be checked and are the schema author's responsibility.
/// - `implicit` on a CHOICE or `Any` doesn't compile.
/// - `SIZE` applies only to types that are `SizeConstrainable`, a value range to
///   `RangeConstrainable` types, and `FROM` to `AlphabetConstrainable` types.
///
/// # Constraints
///
/// `constraint` takes X.680 notation: single values, ranges with `MIN`, `MAX` and exclusive
/// ends (`0<..<10`), `SIZE (...)`, `FROM ("a".."z")`, the operators `|`/`UNION`,
/// `^`/`INTERSECTION`, `EXCEPT` and `ALL EXCEPT` with parentheses, named integer `const`s as
/// bounds, and an extension marker (`SIZE (1..8, ...)`), which is parsed but not enforced.
/// `CONTAINING`, `WITH COMPONENT(S)`, `CONSTRAINED BY`, `PATTERN`, `INCLUDES` and table
/// constraints are rejected with a pointer to the alternative.
///
/// # Example
///
/// ```ignore
/// #[derive(Asn1)]
/// #[asn1(transparent, constraint = "SIZE (6 | 8 | 12 | 16)")]
/// pub struct MacAddress<'a>(pub OctetString<'a>);
/// ```
#[proc_macro_derive(Asn1, attributes(asn1))]
pub fn derive_asn1(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input).unwrap_or_else(syn::Error::into_compile_error).into()
}

/// Produces an `Oid<'static>` from a dotted string such as `"1.2.840.113549"`, checking it at
/// compile time.
#[proc_macro]
pub fn oid(input: TokenStream) -> TokenStream {
    oid::expand(input.into()).unwrap_or_else(syn::Error::into_compile_error).into()
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let attrs = attrs::container(&input.attrs)?;
    match &input.data {
        syn::Data::Struct(data) => structs::expand(input, data, &attrs),
        syn::Data::Enum(data) => choice::expand(input, data, &attrs),
        syn::Data::Union(_) => {
            Err(syn::Error::new_spanned(&input.ident, "unions can't be ASN.1 types"))
        }
    }
}

pub(crate) fn library() -> TokenStream2 {
    quote!(::bouncycastle_asn1)
}

pub(crate) fn error_kind(kind: TokenStream2, offset: TokenStream2) -> TokenStream2 {
    let lib = library();
    quote!(#lib::Error::new(#lib::ErrorKind::#kind, #offset))
}

/// Generics split for impl blocks, with a lifetime for the decoded data.
pub(crate) struct Gen {
    impl_generics: TokenStream2,
    ty_generics: TokenStream2,
    predicates: Vec<TokenStream2>,
    pub lt: Lifetime,
}

impl Gen {
    /// The type's own generics. `lt` is its first lifetime, or a placeholder.
    pub fn plain(input: &DeriveInput) -> Gen {
        let lt = input
            .generics
            .lifetimes()
            .next()
            .map_or_else(|| Lifetime::new("'__asn1", Span::call_site()), |l| l.lifetime.clone());
        Self::build(&input.generics, lt)
    }

    /// The type's generics, plus a lifetime parameter if it has none.
    pub fn decode(input: &DeriveInput) -> Gen {
        let mut generics = input.generics.clone();
        let lt = match generics.lifetimes().next() {
            Some(l) => l.lifetime.clone(),
            None => {
                let lt = Lifetime::new("'__asn1", Span::call_site());
                generics.params.insert(0, parse_quote!(#lt));
                lt
            }
        };
        let mut built = Self::build(&generics, lt);
        // The type itself is written without the added lifetime.
        let (_, ty_generics, _) = input.generics.split_for_impl();
        built.ty_generics = quote!(#ty_generics);
        built
    }

    fn build(generics: &syn::Generics, lt: Lifetime) -> Gen {
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
        Gen {
            impl_generics: quote!(#impl_generics),
            ty_generics: quote!(#ty_generics),
            predicates: where_clause
                .map(|w| w.predicates.iter().map(|p| quote!(#p)).collect())
                .unwrap_or_default(),
            lt,
        }
    }

    pub fn impl_generics(&self) -> &TokenStream2 {
        &self.impl_generics
    }

    pub fn ty_generics(&self) -> &TokenStream2 {
        &self.ty_generics
    }

    /// A where clause holding the type's own predicates and `extra`.
    pub fn where_clause(&self, extra: &[TokenStream2]) -> TokenStream2 {
        let all: Vec<_> = self.predicates.iter().chain(extra).collect();
        if all.is_empty() { TokenStream2::new() } else { quote!(where #( #all ),*) }
    }
}
