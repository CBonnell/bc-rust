//! Shared analysis of struct fields.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Field, Ident, Result, Type};

use crate::attrs::{self, FieldAttrs, Tagging, Tolerance};

pub struct FieldInfo {
    pub index: usize,
    pub member: TokenStream,
    pub bind: Ident,
    pub ty: Type,
    /// `T` for `Option<T>`, otherwise the field type.
    pub value_ty: Type,
    pub optional: bool,
    pub unknown: bool,
    pub attrs: FieldAttrs,
}

pub fn analyze(index: usize, field: &Field) -> Result<FieldInfo> {
    let attrs = attrs::field(&field.attrs)?;
    let member = match &field.ident {
        Some(name) => quote!(#name),
        None => {
            let i = syn::Index::from(index);
            quote!(#i)
        }
    };
    let (optional, value_ty) = match attrs::option_inner(&field.ty) {
        Some(inner) => (true, inner.clone()),
        None => (false, field.ty.clone()),
    };
    let unknown = attrs::last_segment_is(&field.ty, "Unknown");
    if optional && attrs.default.is_some() {
        return Err(syn::Error::new_spanned(
            &field.ty,
            "a field can't be both `Option` and have a `default`",
        ));
    }
    Ok(FieldInfo {
        index,
        member,
        bind: format_ident!("__asn1_f{index}"),
        ty: field.ty.clone(),
        value_ty,
        optional,
        unknown,
        attrs,
    })
}

impl FieldInfo {
    /// The type that is actually read from the wire.
    pub fn wire(&self) -> TokenStream {
        let ty = &self.value_ty;
        match &self.attrs.tagging {
            Tagging::None => quote!(#ty),
            Tagging::Explicit(n) => quote!(::bouncycastle_asn1::Explicit<#n, #ty>),
            Tagging::Implicit(n) => quote!(::bouncycastle_asn1::Implicit<#n, #ty>),
        }
    }

    /// Extracts the value from the wire wrapper.
    pub fn unwrap(&self, w: TokenStream) -> TokenStream {
        match self.attrs.tagging {
            Tagging::None => w,
            _ => quote!(#w.0),
        }
    }

    /// Wraps a `Result`-returning expression over `contents` in the field's `der` and
    /// `tolerate` handling.
    pub fn wrap_read(&self, mut inner: TokenStream) -> TokenStream {
        for t in &self.attrs.tolerate {
            if *t == Tolerance::UnsortedSetOf {
                inner = quote! {
                    contents.with_tolerance(::bouncycastle_asn1::Tolerance::UnsortedSetOf, |contents| #inner)
                };
            }
        }
        if self.attrs.der {
            inner = quote! {
                contents.tighten_rules(::bouncycastle_asn1::Rules::Der, |contents| #inner)
            };
        }
        inner
    }

    pub fn tolerates_encoded_default(&self) -> bool {
        self.attrs.tolerate.contains(&Tolerance::EncodedDefault)
    }

    /// Statements that return `ConstraintViolated` unless the field's constraints and
    /// `validate` hook hold for `value`, a reference expression.
    pub fn checks(&self, value: &TokenStream, on_error: &TokenStream) -> Result<TokenStream> {
        let mut conditions = crate::constraint::check_expr(&self.attrs.constraints, value)?;
        if let Some(path) = &self.attrs.validate {
            conditions.push(quote!(#path(#value)));
        }
        Ok(quote! { #( if !(#conditions) { return Err(#on_error); } )* })
    }
}

/// `ty` with every lifetime replaced by `'static`, for item-level assertions that can't name
/// the type's lifetime parameters.
pub fn erase_lifetimes(ty: &Type) -> Type {
    struct Erase;
    impl syn::visit_mut::VisitMut for Erase {
        fn visit_lifetime_mut(&mut self, lt: &mut syn::Lifetime) {
            *lt = syn::Lifetime::new("'static", lt.span());
        }
        fn visit_type_reference_mut(&mut self, r: &mut syn::TypeReference) {
            if r.lifetime.is_none() {
                r.lifetime = Some(syn::Lifetime::new("'static", proc_macro2::Span::call_site()));
            }
            syn::visit_mut::visit_type_reference_mut(self, r);
        }
    }
    let mut ty = ty.clone();
    syn::visit_mut::VisitMut::visit_type_mut(&mut Erase, &mut ty);
    ty
}

impl FieldInfo {
    /// The wire type with lifetimes erased.
    pub fn static_wire(&self) -> TokenStream {
        let ty = erase_lifetimes(&self.value_ty);
        match &self.attrs.tagging {
            Tagging::None => quote!(#ty),
            Tagging::Explicit(n) => quote!(::bouncycastle_asn1::Explicit<#n, #ty>),
            Tagging::Implicit(n) => quote!(::bouncycastle_asn1::Implicit<#n, #ty>),
        }
    }
}

pub fn tags_of(field: &FieldInfo) -> TokenStream {
    let wire = field.static_wire();
    quote!(<#wire as ::bouncycastle_asn1::StaticTags>::TAGS)
}
