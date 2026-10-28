use proc_macro2::TokenStream;
use quote::quote;
use syn::{LitStr, Result};

fn base128(mut v: u128, out: &mut Vec<u8>) {
    let mut digits = vec![(v & 0x7F) as u8];
    v >>= 7;
    while v > 0 {
        digits.push((v & 0x7F) as u8 | 0x80);
        v >>= 7;
    }
    out.extend(digits.into_iter().rev());
}

pub fn expand(input: TokenStream) -> Result<TokenStream> {
    let text: LitStr = syn::parse2(input)?;
    let fail = |m: &str| syn::Error::new(text.span(), format!("invalid object identifier: {m}"));
    let arcs = text
        .value()
        .split('.')
        .map(|part| part.parse::<u128>().map_err(|_| fail("arcs are non-negative integers")))
        .collect::<Result<Vec<_>>>()?;
    let [first, second, rest @ ..] = arcs.as_slice() else {
        return Err(fail("at least two arcs are required"));
    };
    if *first > 2 || (*first < 2 && *second >= 40) {
        return Err(fail(
            "the first arc must be 0, 1 or 2, and the second below 40 unless it is 2",
        ));
    }
    let head = first
        .checked_mul(40)
        .and_then(|v| v.checked_add(*second))
        .ok_or_else(|| fail("arc too large"))?;
    let mut bytes = Vec::new();
    base128(head, &mut bytes);
    for arc in rest {
        base128(*arc, &mut bytes);
    }
    Ok(quote! {{
        const OID: ::bouncycastle_asn1::Oid<'static> =
            match ::bouncycastle_asn1::Oid::new(&[ #( #bytes ),* ]) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => panic!("invalid object identifier"),
            };
        OID
    }})
}
