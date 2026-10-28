#![no_main]

use bouncycastle_asn1::*;
use libfuzzer_sys::fuzz_target;

/// Decoding never panics, and DER decode-then-encode gives the same bytes.
fn check<'a, T: ContentCodec<'a>>(bytes: &'a [u8]) {
    let _ = T::decode_content(bytes, Rules::Ber);
    if let Ok(value) = T::decode_content(bytes, Rules::Der) {
        let mut out = vec![0u8; bytes.len() + 8];
        assert_eq!(value.content_len(), bytes.len());
        let n = value.encode_content(&mut out).expect("a decoded value encodes");
        assert_eq!(&out[..n], bytes);
    }
}

fuzz_target!(|bytes: &[u8]| {
    check::<bool>(bytes);
    check::<Int>(bytes);
    check::<Enumerated>(bytes);
    check::<Null>(bytes);
    check::<Oid>(bytes);
    check::<RelOid>(bytes);
    check::<BitString>(bytes);
    check::<NamedBits>(bytes);
    check::<OctetString>(bytes);
    check::<Utf8String>(bytes);
    check::<PrintableString>(bytes);
    check::<Ia5String>(bytes);
    check::<VisibleString>(bytes);
    check::<NumericString>(bytes);
    check::<BmpString>(bytes);
    check::<UniversalString>(bytes);
    check::<TeletexString>(bytes);
    check::<UtcTime>(bytes);
    check::<GeneralizedTime>(bytes);
    check::<i8>(bytes);
    check::<i16>(bytes);
    check::<i32>(bytes);
    check::<i64>(bytes);
    check::<i128>(bytes);
    check::<u8>(bytes);
    check::<u16>(bytes);
    check::<u32>(bytes);
    check::<u64>(bytes);
    check::<u128>(bytes);
});
