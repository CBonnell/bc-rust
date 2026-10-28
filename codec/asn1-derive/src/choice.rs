//! Code generation for enums: CHOICE.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Fields, Result, Variant};

use crate::attrs::{self, ContainerAttrs, Tagging};
use crate::{Gen, error_kind, library};

struct Alt<'v> {
    variant: &'v Variant,
    ty: syn::Type,
    tagging: Tagging,
    unknown: bool,
}

impl Alt<'_> {
    fn wire(&self) -> TokenStream {
        let ty = &self.ty;
        match &self.tagging {
            Tagging::None => quote!(#ty),
            Tagging::Explicit(n) => quote!(::bouncycastle_asn1::Explicit<#n, #ty>),
            Tagging::Implicit(n) => quote!(::bouncycastle_asn1::Implicit<#n, #ty>),
        }
    }

    fn static_wire(&self) -> TokenStream {
        let ty = crate::fields::erase_lifetimes(&self.ty);
        match &self.tagging {
            Tagging::None => quote!(#ty),
            Tagging::Explicit(n) => quote!(::bouncycastle_asn1::Explicit<#n, #ty>),
            Tagging::Implicit(n) => quote!(::bouncycastle_asn1::Implicit<#n, #ty>),
        }
    }

    fn unwrap(&self, w: TokenStream) -> TokenStream {
        match self.tagging {
            Tagging::None => w,
            _ => quote!(#w.0),
        }
    }
}

pub fn expand(
    input: &DeriveInput,
    data: &syn::DataEnum,
    attrs: &ContainerAttrs,
) -> Result<TokenStream> {
    let lib = library();
    if attrs.transparent || attrs.set {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`set` and `transparent` apply to structs",
        ));
    }
    let mut alts = Vec::new();
    for variant in &data.variants {
        let Fields::Unnamed(fields) = &variant.fields else {
            return Err(syn::Error::new_spanned(
                variant,
                "CHOICE alternatives must be tuple variants with one field",
            ));
        };
        let mut iter = fields.unnamed.iter();
        let (Some(field), None) = (iter.next(), iter.next()) else {
            return Err(syn::Error::new_spanned(
                variant,
                "CHOICE alternatives hold exactly one value",
            ));
        };
        let field_attrs = attrs::field(&variant.attrs)?;
        let unknown = attrs.extensible
            && variant.ident == "Unknown"
            && attrs::last_segment_is(&field.ty, "Any");
        alts.push(Alt { variant, ty: field.ty.clone(), tagging: field_attrs.tagging, unknown });
    }
    let name = &input.ident;
    let decode_gen = Gen::decode(input);
    let plain_gen = Gen::plain(input);
    let (lt, decode_impl, decode_ty) =
        (&decode_gen.lt, decode_gen.impl_generics(), decode_gen.ty_generics());
    let decode_where = decode_gen.where_clause(&[]);
    let (plain_impl, plain_ty) = (plain_gen.impl_generics(), plain_gen.ty_generics());
    let plain_where = plain_gen.where_clause(&[]);

    let known: Vec<&Alt> = alts.iter().filter(|a| !a.unknown).collect();
    let tag_lists: Vec<TokenStream> = known
        .iter()
        .map(|a| {
            let wire = a.wire();
            quote!(<#wire as #lib::StaticTags>::TAGS)
        })
        .collect();
    let static_lists: Vec<TokenStream> = known
        .iter()
        .map(|a| {
            let wire = a.static_wire();
            quote!(<#wire as #lib::StaticTags>::TAGS)
        })
        .collect();
    let distinct = if input.generics.type_params().next().is_none() {
        quote! {
            const _: () = assert!(
                #lib::TagList::all_distinct(&[ #( &#static_lists ),* ]),
                "CHOICE alternatives must have distinct tags"
            );
        }
    } else {
        TokenStream::new()
    };

    let decode_arms = alts.iter().filter(|a| !a.unknown).map(|a| {
        let (wire, variant) = (a.wire(), &a.variant.ident);
        let value = a.unwrap(quote!(__asn1_w));
        quote! {
            if <#wire as #lib::MatchTag>::matches_tag(__asn1_tag) {
                return r.read::<#wire>().map(|__asn1_w| #name::#variant(#value));
            }
        }
    });
    let unknown_decode = alts.iter().find(|a| a.unknown).map(|a| {
        let variant = &a.variant.ident;
        quote!( return r.read::<#lib::Any<#lt>>().map(#name::#variant); )
    });
    let fallthrough = if unknown_decode.is_some() {
        TokenStream::new()
    } else {
        quote! {
            Err(#lib::Error::new(
                #lib::ErrorKind::UnexpectedTag { expected: ::core::option::Option::None, found: __asn1_tag },
                r.offset(),
            ))
        }
    };
    let truncated = error_kind(quote!(Truncated), quote!(r.offset()));
    let match_tag = alts.iter().map(|a| {
        if a.unknown {
            quote!(true)
        } else {
            let wire = a.wire();
            quote!(<#wire as #lib::MatchTag>::matches_tag(tag))
        }
    });
    let len_arms = alts.iter().map(|a| {
        let variant = &a.variant.ident;
        let call = encode_call(a, true);
        quote!( #name::#variant(__asn1_v) => #call, )
    });
    let write_arms = alts.iter().map(|a| {
        let variant = &a.variant.ident;
        let call = encode_call(a, false);
        quote!( #name::#variant(__asn1_v) => #call, )
    });

    Ok(quote! {
        #distinct

        impl #decode_impl #lib::Decode<#lt> for #name #decode_ty #decode_where {
            fn decode(r: &mut #lib::SliceReader<#lt>) -> ::core::result::Result<Self, #lib::Error> {
                let __asn1_tag = r.peek_tag()?.ok_or(#truncated)?;
                #( #decode_arms )*
                #unknown_decode
                #fallthrough
            }
        }

        impl #plain_impl #lib::MatchTag for #name #plain_ty #plain_where {
            fn matches_tag(tag: #lib::Tag) -> bool {
                false #( || #match_tag )*
            }
        }

        impl #plain_impl #lib::StaticTags for #name #plain_ty #plain_where {
            const TAGS: #lib::TagList = #lib::TagList::EMPTY #( .extend(&#tag_lists) )*;
        }

        impl #plain_impl #lib::Encode for #name #plain_ty #plain_where {
            fn encoded_len(&self) -> ::core::result::Result<u64, #lib::Error> {
                match self { #( #len_arms )* }
            }

            fn encode(&self, w: &mut #lib::Writer<'_>) -> ::core::result::Result<(), #lib::Error> {
                match self { #( #write_arms )* }
            }
        }
    })
}

fn encode_call(a: &Alt, length: bool) -> TokenStream {
    let lib = library();
    match (&a.tagging, length) {
        (Tagging::None, true) => quote!(#lib::Encode::encoded_len(__asn1_v)),
        (Tagging::None, false) => quote!(#lib::Encode::encode(__asn1_v, w)),
        (Tagging::Explicit(n), true) => quote!(#lib::Explicit::<#n, _>::encoded_len_of(__asn1_v)),
        (Tagging::Explicit(n), false) => quote!(#lib::Explicit::<#n, _>::encode_of(__asn1_v, w)),
        (Tagging::Implicit(n), true) => quote!(#lib::Implicit::<#n, _>::encoded_len_of(__asn1_v)),
        (Tagging::Implicit(n), false) => quote!(#lib::Implicit::<#n, _>::encode_of(__asn1_v, w)),
    }
}
