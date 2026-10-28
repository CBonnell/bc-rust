//! Code generation for structs: SEQUENCE, SET and transparent wrappers.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Fields, Result};

use crate::attrs::{ContainerAttrs, Tagging};
use crate::fields::{self, FieldInfo, tags_of};
use crate::{Gen, error_kind, library};

pub fn expand(
    input: &DeriveInput,
    data: &syn::DataStruct,
    attrs: &ContainerAttrs,
) -> Result<TokenStream> {
    if attrs.transparent {
        return transparent(input, data, attrs);
    }
    let infos = data
        .fields
        .iter()
        .enumerate()
        .map(|(i, f)| fields::analyze(i, f))
        .collect::<Result<Vec<_>>>()?;
    for field in &infos {
        if field.unknown && field.index + 1 != infos.len() {
            return Err(syn::Error::new_spanned(&field.ty, "`Unknown` must be the last field"));
        }
    }
    let extensible = attrs.extensible || infos.iter().any(|f| f.unknown);
    let name = &input.ident;
    let lib = library();
    let decode_gen = Gen::decode(input);
    let plain_gen = Gen::plain(input);
    let (lt, decode_impl, decode_ty) =
        (&decode_gen.lt, decode_gen.impl_generics(), decode_gen.ty_generics());
    let decode_where = decode_gen.where_clause(&[]);
    let (plain_impl, plain_ty) = (plain_gen.impl_generics(), plain_gen.ty_generics());
    let plain_where = plain_gen.where_clause(&[]);
    let tag = if attrs.set { quote!(#lib::Tag::SET) } else { quote!(#lib::Tag::SEQUENCE) };

    let decode_body = if attrs.set {
        set_decode(&infos, extensible)?
    } else {
        sequence_decode(&infos, extensible)?
    };
    let construct = construct(name, &data.fields, &infos);
    let validate_decode = attrs.validate.as_ref().map(|path| {
        quote! { if !#path(&__asn1_value) {
            return Err(#lib::Error::new(#lib::ErrorKind::ConstraintViolated, header.offset()));
        } }
    });
    let const_checks = if input.generics.type_params().next().is_none() {
        static_checks(&infos, attrs.set)
    } else {
        TokenStream::new()
    };
    let (len_body, write_body) = encode_bodies(&infos, attrs)?;

    Ok(quote! {
        #const_checks

        impl #plain_impl #lib::FixedTag for #name #plain_ty #plain_where {
            const TAG: #lib::Tag = #tag;
            const CONSTRUCTED: bool = true;
        }

        impl #decode_impl #lib::DecodeValue<#lt> for #name #decode_ty #decode_where {
            fn decode_value(
                header: &#lib::Header<#lt>,
                contents: &mut #lib::SliceReader<#lt>,
            ) -> ::core::result::Result<Self, #lib::Error> {
                if !header.constructed() {
                    return Err(#lib::Error::new(#lib::ErrorKind::WrongUniversalForm, header.offset()));
                }
                #decode_body
                let __asn1_value = #construct;
                #validate_decode
                Ok(__asn1_value)
            }
        }

        impl #plain_impl #lib::EncodeValue for #name #plain_ty #plain_where {
            fn value_len(&self) -> ::core::result::Result<u64, #lib::Error> {
                #len_body
            }

            fn encode_value(
                &self,
                w: &mut #lib::Writer<'_>,
            ) -> ::core::result::Result<(), #lib::Error> {
                #write_body
            }
        }
    })
}

fn construct(name: &syn::Ident, fields: &Fields, infos: &[FieldInfo]) -> TokenStream {
    let binds = infos.iter().map(|f| &f.bind);
    match fields {
        Fields::Named(_) => {
            let members = infos.iter().map(|f| &f.member);
            quote!(#name { #( #members: #binds ),* })
        }
        Fields::Unnamed(_) => quote!(#name( #( #binds ),* )),
        Fields::Unit => quote!(#name),
    }
}

/// Compile-time rejection of ambiguous tags where they are static.
fn static_checks(infos: &[FieldInfo], set: bool) -> TokenStream {
    let lib = library();
    let mut groups: Vec<Vec<&FieldInfo>> = Vec::new();
    if set {
        groups.push(infos.iter().filter(|f| !f.unknown).collect());
    } else {
        let mut run: Vec<&FieldInfo> = Vec::new();
        for f in infos.iter().filter(|f| !f.unknown) {
            run.push(f);
            if !(f.optional || f.attrs.default.is_some()) {
                groups.push(core::mem::take(&mut run));
            }
        }
        if !run.is_empty() {
            groups.push(run);
        }
    }
    let message = if set {
        "SET components must have distinct tags"
    } else {
        "OPTIONAL and DEFAULT fields must have tags distinct from the fields that can follow them"
    };
    let asserts = groups.iter().filter(|g| g.len() > 1).map(|g| {
        let lists = g.iter().map(|f| tags_of(f));
        quote! { const _: () = assert!(#lib::TagList::all_distinct(&[ #( &#lists ),* ]), #message); }
    });
    let single = set
        .then(|| {
            infos.iter().filter(|f| !f.unknown).map(|f| {
                let tags = tags_of(f);
                quote! { const _: () = assert!(#tags.len() == 1, "SET components need one static tag; use explicit or implicit tagging for a CHOICE"); }
            })
        })
        .into_iter()
        .flatten();
    quote!( #( #asserts )* #( #single )* )
}

fn field_value(f: &FieldInfo) -> syn::Result<TokenStream> {
    let lib = library();
    let wire = f.wire();
    let bind = &f.bind;
    if f.unknown {
        return Ok(quote!(let #bind = contents.read_unknown()?;));
    }
    let on_error = error_kind(quote!(ConstraintViolated), quote!(__asn1_start));
    let value = if f.optional {
        let read = f.wrap_read(quote!(contents.read_optional::<#wire>()));
        let unwrapped = f.unwrap(quote!(__asn1_w));
        let checks = f.checks(&quote!(__asn1_v), &on_error)?;
        quote! {
            let __asn1_read: ::core::option::Option<#wire> = #read?;
            let #bind = __asn1_read.map(|__asn1_w| #unwrapped);
            if let ::core::option::Option::Some(__asn1_v) = &#bind { #checks }
        }
    } else if let Some(default) = &f.attrs.default {
        let ty = &f.value_ty;
        let read = f.wrap_read(quote!(contents.read_optional::<#wire>()));
        let unwrapped = f.unwrap(quote!(__asn1_w));
        let checks = f.checks(&quote!(&#bind), &on_error)?;
        let tolerated = if f.tolerates_encoded_default() {
            quote! {
                if contents.config().tolerances().contains(#lib::Tolerance::EncodedDefault) {
                    contents.record_deviation(#lib::Tolerance::EncodedDefault);
                } else {
                    return Err(#lib::Error::new(#lib::ErrorKind::DefaultValueEncoded, __asn1_start));
                }
            }
        } else {
            quote!(return Err(#lib::Error::new(#lib::ErrorKind::DefaultValueEncoded, __asn1_start));)
        };
        quote! {
            let __asn1_default: #ty = #default;
            let __asn1_read: ::core::option::Option<#wire> = #read?;
            let #bind: #ty = match __asn1_read {
                ::core::option::Option::Some(__asn1_w) => {
                    let __asn1_v: #ty = #unwrapped;
                    if __asn1_v == __asn1_default && contents.rules() == #lib::Rules::Der {
                        #tolerated
                    }
                    __asn1_v
                }
                ::core::option::Option::None => __asn1_default,
            };
            #checks
        }
    } else {
        let ty = &f.value_ty;
        let read = f.wrap_read(quote!(contents.read::<#wire>()));
        let unwrapped = f.unwrap(quote!(__asn1_w));
        let checks = f.checks(&quote!(&#bind), &on_error)?;
        quote! {
            let __asn1_w: #wire = #read?;
            let #bind: #ty = #unwrapped;
            #checks
        }
    };
    Ok(quote! {
        let __asn1_start = contents.offset();
        #value
    })
}

fn defined_by_check(infos: &[FieldInfo]) -> Result<TokenStream> {
    let mut out = TokenStream::new();
    for f in infos {
        let Some((target, set)) = &f.attrs.defined_by else { continue };
        let target_name = target.value();
        let other = infos
            .iter()
            .find(|o| o.member.to_string() == target_name)
            .ok_or_else(|| syn::Error::new(target.span(), "no such field"))?;
        let (oid, any) = (&other.bind, &f.bind);
        let lib = library();
        let call = quote! {
            <#set as #lib::DefinedBySet>::decode_defined(&#oid, __asn1_open.clone())?;
        };
        out.extend(if f.optional {
            quote!( if let ::core::option::Option::Some(__asn1_open) = &#any { #call } )
        } else {
            quote!( { let __asn1_open = &#any; #call } )
        });
    }
    Ok(out)
}

fn sequence_decode(infos: &[FieldInfo], extensible: bool) -> Result<TokenStream> {
    let values = infos.iter().map(field_value).collect::<Result<Vec<_>>>()?;
    let defined = defined_by_check(infos)?;
    let skip = (extensible && !infos.iter().any(|f| f.unknown))
        .then(|| quote!(contents.skip_remaining()?;));
    Ok(quote! { #( #values )* #skip #defined })
}

fn set_decode(infos: &[FieldInfo], extensible: bool) -> Result<TokenStream> {
    let lib = library();
    let regular: Vec<&FieldInfo> = infos.iter().filter(|f| !f.unknown).collect();
    let slots = regular.iter().map(|f| {
        let slot = quote::format_ident!("__asn1_slot{}", f.index);
        let wire = f.wire();
        quote!(let mut #slot: ::core::option::Option<#wire> = ::core::option::Option::None;)
    });
    let arms = regular.iter().map(|f| {
        let slot = quote::format_ident!("__asn1_slot{}", f.index);
        let wire = f.wire();
        let read = f.wrap_read(quote!(contents.read::<#wire>()));
        quote! {
            if <#wire as #lib::MatchTag>::matches_tag(__asn1_tag) {
                if #slot.is_some() {
                    return Err(#lib::Error::new(
                        #lib::ErrorKind::UnexpectedTag { expected: ::core::option::Option::None, found: __asn1_tag },
                        __asn1_at,
                    ));
                }
                #slot = ::core::option::Option::Some(#read?);
                continue;
            }
        }
    });
    let unmatched = if extensible {
        quote!(contents.read::<#lib::Any>()?;)
    } else {
        quote! {
            return Err(#lib::Error::new(
                #lib::ErrorKind::UnexpectedTag { expected: ::core::option::Option::None, found: __asn1_tag },
                __asn1_at,
            ));
        }
    };
    let finals = regular.iter().map(|f| -> Result<TokenStream> {
        let slot = quote::format_ident!("__asn1_slot{}", f.index);
        let bind = &f.bind;
        let ty = &f.ty;
        let unwrapped = f.unwrap(quote!(__asn1_w));
        let on_error = error_kind(quote!(ConstraintViolated), quote!(header.offset()));
        let missing = quote!(#lib::Error::new(#lib::ErrorKind::Truncated, contents.offset()));
        if f.optional {
            let checks = f.checks(&quote!(__asn1_v), &on_error)?;
            Ok(quote! {
                let #bind: #ty = #slot.map(|__asn1_w| #unwrapped);
                if let ::core::option::Option::Some(__asn1_v) = &#bind { #checks }
            })
        } else if let Some(default) = &f.attrs.default {
            let checks = f.checks(&quote!(&#bind), &on_error)?;
            let vt = &f.value_ty;
            let encoded = if f.tolerates_encoded_default() {
                quote! {
                    if contents.config().tolerances().contains(#lib::Tolerance::EncodedDefault) {
                        contents.record_deviation(#lib::Tolerance::EncodedDefault);
                    } else {
                        return Err(#lib::Error::new(#lib::ErrorKind::DefaultValueEncoded, header.offset()));
                    }
                }
            } else {
                quote!(return Err(#lib::Error::new(#lib::ErrorKind::DefaultValueEncoded, header.offset()));)
            };
            Ok(quote! {
                let __asn1_default: #vt = #default;
                let #bind: #ty = match #slot {
                    ::core::option::Option::Some(__asn1_w) => {
                        let __asn1_v: #vt = #unwrapped;
                        if __asn1_v == __asn1_default && contents.rules() == #lib::Rules::Der { #encoded }
                        __asn1_v
                    }
                    ::core::option::Option::None => __asn1_default,
                };
                #checks
            })
        } else {
            let checks = f.checks(&quote!(&#bind), &on_error)?;
            Ok(quote! {
                let __asn1_w = #slot.ok_or(#missing)?;
                let #bind: #ty = #unwrapped;
                #checks
            })
        }
    }).collect::<Result<Vec<_>>>()?;
    let unknown_binds = infos.iter().filter(|f| f.unknown).map(|f| {
        let bind = &f.bind;
        quote!(let #bind = contents.read_unknown()?;)
    });
    let defined = defined_by_check(infos)?;
    Ok(quote! {
        #( #slots )*
        let mut __asn1_previous: ::core::option::Option<#lib::Tag> = ::core::option::Option::None;
        while let ::core::option::Option::Some(__asn1_tag) = contents.peek_tag()? {
            let __asn1_at = contents.offset();
            if contents.rules() == #lib::Rules::Der
                && __asn1_previous.is_some_and(|p| p > __asn1_tag)
            {
                return Err(#lib::Error::new(#lib::ErrorKind::SetOfNotSorted, __asn1_at));
            }
            __asn1_previous = ::core::option::Option::Some(__asn1_tag);
            #( #arms )*
            #unmatched
        }
        #( #finals )*
        #( #unknown_binds )*
        #defined
    })
}

fn wrapper_calls(f: &FieldInfo, v: &TokenStream) -> (TokenStream, TokenStream) {
    let lib = library();
    match &f.attrs.tagging {
        _ if f.unknown => {
            (quote!(#lib::Encode::encoded_len(#v)?), quote!(#lib::Encode::encode(#v, w)?))
        }
        Tagging::None => {
            (quote!(#lib::Encode::encoded_len(#v)?), quote!(#lib::Encode::encode(#v, w)?))
        }
        Tagging::Explicit(n) => (
            quote!(#lib::Explicit::<#n, _>::encoded_len_of(#v)?),
            quote!(#lib::Explicit::<#n, _>::encode_of(#v, w)?),
        ),
        Tagging::Implicit(n) => (
            quote!(#lib::Implicit::<#n, _>::encoded_len_of(#v)?),
            quote!(#lib::Implicit::<#n, _>::encode_of(#v, w)?),
        ),
    }
}

/// Wraps `action`, which uses `__asn1_v: &T`, in the presence test for `f`.
fn when_present(f: &FieldInfo, action: &TokenStream) -> TokenStream {
    let m = &f.member;
    if f.optional {
        quote!( if let ::core::option::Option::Some(__asn1_v) = &self.#m { #action } )
    } else if let Some(default) = &f.attrs.default {
        let ty = &f.value_ty;
        quote! {{
            let __asn1_default: #ty = #default;
            if self.#m != __asn1_default { let __asn1_v = &self.#m; #action }
        }}
    } else {
        quote!({ let __asn1_v = &self.#m; #action })
    }
}

fn encode_bodies(
    infos: &[FieldInfo],
    attrs: &ContainerAttrs,
) -> Result<(TokenStream, TokenStream)> {
    let lib = library();
    let on_error = error_kind(quote!(ConstraintViolated), quote!(0));
    let mut checks = TokenStream::new();
    for f in infos.iter().filter(|f| !f.unknown) {
        let m = &f.member;
        let c = f.checks(&quote!(__asn1_v), &on_error)?;
        checks.extend(if f.optional {
            quote!( if let ::core::option::Option::Some(__asn1_v) = &self.#m { #c } )
        } else {
            quote!({ let __asn1_v = &self.#m; #c })
        });
    }
    if let Some(path) = &attrs.validate {
        checks.extend(quote!( if !#path(self) { return Err(#on_error); } ));
    }
    let lens = infos.iter().map(|f| {
        let (len, _) = wrapper_calls(f, &quote!(__asn1_v));
        when_present(f, &quote!( __asn1_len += #len; ))
    });
    let len_body = quote! {
        #checks
        let mut __asn1_len = 0u64;
        #( #lens )*
        Ok(__asn1_len)
    };

    let write_body = if attrs.set {
        let regular: Vec<&FieldInfo> = infos.iter().filter(|f| !f.unknown).collect();
        let count = regular.len();
        let pushes = regular.iter().map(|f| {
            let (index, tags) = (f.index, tags_of(f));
            when_present(f, &quote!( __asn1_order.push(#tags.first(), #index); ))
        });
        let arms = regular.iter().map(|f| {
            let index = f.index;
            let (_, write) = wrapper_calls(f, &quote!(__asn1_v));
            let body = when_present(f, &quote!( #write; ));
            quote!( #index => #body, )
        });
        let unknown = infos.iter().filter(|f| f.unknown).map(|f| {
            let (_, write) = wrapper_calls(f, &quote!(__asn1_v));
            when_present(f, &quote!( #write; ))
        });
        quote! {
            let mut __asn1_order = #lib::SetOrder::<#count>::new();
            #( #pushes )*
            for &(_, __asn1_index) in __asn1_order.sorted() {
                match __asn1_index {
                    #( #arms )*
                    _ => {}
                }
            }
            #( #unknown )*
            Ok(())
        }
    } else {
        let writes = infos.iter().map(|f| {
            let (_, write) = wrapper_calls(f, &quote!(__asn1_v));
            when_present(f, &quote!( #write; ))
        });
        quote! { #( #writes )* Ok(()) }
    };
    Ok((len_body, write_body))
}

fn transparent(
    input: &DeriveInput,
    data: &syn::DataStruct,
    attrs: &ContainerAttrs,
) -> Result<TokenStream> {
    let lib = library();
    let mut fields = data.fields.iter();
    let (Some(field), None) = (fields.next(), fields.next()) else {
        return Err(syn::Error::new_spanned(&input.ident, "`transparent` needs exactly one field"));
    };
    let name = &input.ident;
    let inner = &field.ty;
    let member = match &field.ident {
        Some(n) => quote!(#n),
        None => quote!(0),
    };
    let build = match &field.ident {
        Some(n) => quote!(#name { #n: __asn1_inner }),
        None => quote!(#name(__asn1_inner)),
    };
    let on_decode = error_kind(quote!(ConstraintViolated), quote!(header.offset()));
    let on_encode = error_kind(quote!(ConstraintViolated), quote!(0));
    let decode_checks = crate::constraint::check_expr(&attrs.constraints, &quote!(&__asn1_inner))?;
    let encode_checks = crate::constraint::check_expr(&attrs.constraints, &quote!(&self.#member))?;
    let validate_decode = attrs
        .validate
        .as_ref()
        .map(|path| quote!( if !#path(&__asn1_self) { return Err(#on_decode); } ));
    let validate_encode =
        attrs.validate.as_ref().map(|path| quote!( if !#path(self) { return Err(#on_encode); } ));

    let decode_gen = Gen::decode(input);
    let plain_gen = Gen::plain(input);
    let (lt, decode_impl, decode_ty) =
        (&decode_gen.lt, decode_gen.impl_generics(), decode_gen.ty_generics());
    let (plain_impl, plain_ty) = (plain_gen.impl_generics(), plain_gen.ty_generics());
    let decode_where = decode_gen.where_clause(&[quote!(#inner: #lib::DecodeValue<#lt>)]);
    let tag_where = plain_gen.where_clause(&[quote!(#inner: #lib::FixedTag)]);
    let encode_where = plain_gen.where_clause(&[quote!(#inner: #lib::EncodeValue)]);

    Ok(quote! {
        impl #plain_impl #lib::FixedTag for #name #plain_ty #tag_where {
            const TAG: #lib::Tag = <#inner as #lib::FixedTag>::TAG;
            const CONSTRUCTED: bool = <#inner as #lib::FixedTag>::CONSTRUCTED;
        }

        impl #decode_impl #lib::DecodeValue<#lt> for #name #decode_ty #decode_where {
            fn decode_value(
                header: &#lib::Header<#lt>,
                contents: &mut #lib::SliceReader<#lt>,
            ) -> ::core::result::Result<Self, #lib::Error> {
                let __asn1_inner =
                    <#inner as #lib::DecodeValue<#lt>>::decode_value(header, contents)?;
                #( if !(#decode_checks) { return Err(#on_decode); } )*
                let __asn1_self = #build;
                #validate_decode
                Ok(__asn1_self)
            }
        }

        impl #plain_impl #lib::EncodeValue for #name #plain_ty #encode_where {
            fn value_len(&self) -> ::core::result::Result<u64, #lib::Error> {
                #( if !(#encode_checks) { return Err(#on_encode); } )*
                #validate_encode
                #lib::EncodeValue::value_len(&self.#member)
            }

            fn encode_value(
                &self,
                w: &mut #lib::Writer<'_>,
            ) -> ::core::result::Result<(), #lib::Error> {
                #lib::EncodeValue::encode_value(&self.#member, w)
            }
        }
    })
}
