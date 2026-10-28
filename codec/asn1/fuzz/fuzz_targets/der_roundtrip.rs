#![no_main]

use bouncycastle_asn1::*;
use bouncycastle_asn1_derive::Asn1;
use libfuzzer_sys::fuzz_target;

#[derive(Asn1, Debug)]
struct Attribute<'a> {
    oid: Oid<'a>,
    #[asn1(constraint = "SIZE (0..4)")]
    values: SetOf<'a, Any<'a>>,
}

#[derive(Asn1, Debug)]
enum Choice<'a> {
    Number(i64),
    Text(Utf8String<'a>),
    #[asn1(explicit = 0)]
    Raw(OctetString<'a>),
    #[asn1(implicit = 1)]
    Bits(BitString<'a>),
}

#[derive(Asn1, Debug)]
struct Schema<'a> {
    #[asn1(explicit = 0, default = 0u8)]
    version: u8,
    serial: Int<'a>,
    #[asn1(default = false)]
    critical: bool,
    #[asn1(implicit = 5)]
    unique_id: Option<BitString<'a>>,
    choice: Choice<'a>,
    when: UtcTime,
    names: SequenceOf<'a, Attribute<'a>>,
    #[asn1(explicit = 2)]
    extra: Option<Any<'a>>,
}

fuzz_target!(|input: &[u8]| {
    let mut r = SliceReader::new(input, &Config::DER);
    let Ok(value) = r.read::<Schema>() else { return };
    if r.finish().is_err() {
        return;
    }
    // Collections decode their elements when reached, so check them all first.
    if value.names.iter().any(|attribute| attribute.is_err()) {
        return;
    }
    let mut out = vec![0u8; input.len() + 16];
    let encoded = encode_to_slice(&value, &mut out).expect("a fully decoded value re-encodes");
    assert_eq!(encoded, input);
});
