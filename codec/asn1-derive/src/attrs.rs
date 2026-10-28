//! Parsing of `#[asn1(...)]` attributes.

use syn::{Attribute, Expr, Ident, LitInt, LitStr, Path, Result, Token, Type};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tolerance {
    EncodedDefault,
    UnsortedSetOf,
}

#[derive(Clone)]
pub enum Tagging {
    None,
    Explicit(LitInt),
    Implicit(LitInt),
}

#[derive(Default)]
pub struct ContainerAttrs {
    pub set: bool,
    pub transparent: bool,
    pub extensible: bool,
    pub constraints: Vec<LitStr>,
    pub validate: Option<Path>,
}

pub struct FieldAttrs {
    pub tagging: Tagging,
    pub default: Option<Expr>,
    pub constraints: Vec<LitStr>,
    pub validate: Option<Path>,
    pub der: bool,
    pub tolerate: Vec<Tolerance>,
    pub defined_by: Option<(LitStr, Type)>,
}

impl Default for FieldAttrs {
    fn default() -> Self {
        FieldAttrs {
            tagging: Tagging::None,
            default: None,
            constraints: Vec::new(),
            validate: None,
            der: false,
            tolerate: Vec::new(),
            defined_by: None,
        }
    }
}

fn each_meta(
    attrs: &[Attribute],
    mut f: impl FnMut(&Ident, syn::meta::ParseNestedMeta<'_>) -> Result<()>,
) -> Result<()> {
    for attr in attrs.iter().filter(|a| a.path().is_ident("asn1")) {
        attr.parse_nested_meta(|meta| {
            let name = meta
                .path
                .get_ident()
                .cloned()
                .ok_or_else(|| meta.error("expected a simple attribute name"))?;
            f(&name, meta)
        })?;
    }
    Ok(())
}

pub fn container(attrs: &[Attribute]) -> Result<ContainerAttrs> {
    let mut out = ContainerAttrs::default();
    each_meta(attrs, |name, meta| {
        match name.to_string().as_str() {
            "set" => out.set = true,
            "transparent" => out.transparent = true,
            "extensible" => out.extensible = true,
            "constraint" => out.constraints.push(meta.value()?.parse()?),
            "validate" => out.validate = Some(meta.value()?.parse()?),
            other => {
                return Err(meta.error(format!("unknown container attribute `{other}`")));
            }
        }
        Ok(())
    })?;
    Ok(out)
}

pub fn field(attrs: &[Attribute]) -> Result<FieldAttrs> {
    let mut out = FieldAttrs::default();
    let mut defined_by: Option<LitStr> = None;
    let mut set: Option<Type> = None;
    each_meta(attrs, |name, meta| {
        match name.to_string().as_str() {
            "explicit" => out.tagging = Tagging::Explicit(meta.value()?.parse()?),
            "implicit" => out.tagging = Tagging::Implicit(meta.value()?.parse()?),
            "default" => out.default = Some(meta.value()?.parse()?),
            "constraint" => out.constraints.push(meta.value()?.parse()?),
            "validate" => out.validate = Some(meta.value()?.parse()?),
            "der" => out.der = true,
            "tolerate" => meta.parse_nested_meta(|inner| {
                if inner.path.is_ident("encoded_default") {
                    out.tolerate.push(Tolerance::EncodedDefault);
                } else if inner.path.is_ident("unsorted_set_of") {
                    out.tolerate.push(Tolerance::UnsortedSetOf);
                } else {
                    return Err(inner.error("expected `encoded_default` or `unsorted_set_of`"));
                }
                Ok(())
            })?,
            "defined_by" => defined_by = Some(meta.value()?.parse()?),
            "set" if meta.input.peek(Token![=]) => set = Some(meta.value()?.parse()?),
            other => return Err(meta.error(format!("unknown field attribute `{other}`"))),
        }
        Ok(())
    })?;
    match (defined_by, set) {
        (Some(field), Some(set)) => out.defined_by = Some((field, set)),
        (None, None) => {}
        (Some(f), None) => {
            return Err(syn::Error::new(f.span(), "`defined_by` needs `set = Type`"));
        }
        (None, Some(t)) => {
            return Err(syn::Error::new_spanned(t, "`set = Type` needs `defined_by = \"field\"`"));
        }
    }
    Ok(out)
}

/// The inner type of `Option<T>`, if `ty` is one.
pub fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else { return None };
    match args.args.first()? {
        syn::GenericArgument::Type(t) => Some(t),
        _ => None,
    }
}

pub fn last_segment_is(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == name))
}
