mod common;

use bouncycastle_asn1::*;
use proptest::prelude::*;

fn id(class: Class, number: u32, constructed: bool) -> Identifier {
    Identifier { tag: Tag { class, number }, constructed }
}

#[test]
fn base128_round_trip_and_sizes() {
    let mut buf = [0u8; 20];
    for v in [0u128, 1, 127, 128, 16_383, 16_384, u64::MAX as u128, u128::MAX] {
        let n = base128::encode(v, &mut buf).unwrap();
        assert_eq!(n, base128::encoded_len(v));
        assert_eq!(base128::decode::<u128>(&buf[..n]).unwrap(), (v, n));
    }
    assert_eq!(base128::encoded_len(0u32), 1);
    assert_eq!(base128::encoded_len(u128::MAX), 19);
}

#[test]
fn base128_errors() {
    let e = base128::decode::<u32>(&[0x80, 0x01]).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::NonMinimalBase128, 0));
    assert_eq!(base128::decode::<u32>(&[0x81, 0x80, 0x01]).unwrap(), (16_385, 3));
    let e = base128::decode::<u32>(&[0x81]).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::Truncated, 1));
    // 2^35 - 1 doesn't fit u32; the overflow is detected before shifting.
    let e = base128::decode::<u32>(&[0xFF, 0xFF, 0xFF, 0xFF, 0x7F]).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::Base128Overflow, 4));
    let mut max = [0u8; 5];
    let n = base128::encode(u32::MAX, &mut max).unwrap();
    assert_eq!(base128::decode::<u32>(&max[..n]).unwrap().0, u32::MAX);
    let mut small = [0u8; 1];
    let e = base128::encode(128u32, &mut small).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::InsufficientSize { required: 2 });
    assert_eq!(small, [0]);
}

proptest! {
    #[test]
    fn base128_round_trips(v in any::<u128>()) {
        let mut buf = [0u8; 19];
        let n = base128::encode(v, &mut buf).unwrap();
        prop_assert_eq!(base128::decode::<u128>(&buf[..n]).unwrap(), (v, n));
        prop_assert!(n == 1 || buf[0] != 0x80);
        if let Ok(small) = u64::try_from(v) {
            prop_assert_eq!(base128::decode::<u64>(&buf[..n]).unwrap().0, small);
        } else {
            let e = base128::decode::<u64>(&buf[..n]).unwrap_err();
            prop_assert_eq!(e.kind(), &ErrorKind::Base128Overflow);
        }
    }

    #[test]
    fn base128_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..24)) {
        let _ = base128::decode::<u32>(&bytes);
        let _ = base128::decode::<u64>(&bytes);
        let _ = base128::decode::<u128>(&bytes);
    }

    #[test]
    fn length_round_trips(v in any::<u64>()) {
        let mut buf = [0u8; 9];
        let l = Length::Definite(v);
        let n = l.encode(&mut buf).unwrap();
        prop_assert_eq!(n, l.encoded_len());
        prop_assert_eq!(Length::decode(&buf[..n], Rules::Der).unwrap(), (l, n));
        prop_assert_eq!(Length::decode(&buf[..n], Rules::Ber).unwrap(), (l, n));
    }

    #[test]
    fn identifier_round_trips(class in 0u8..4, number in 0u32..=16_383, constructed in any::<bool>()) {
        let class = [Class::Universal, Class::Application, Class::ContextSpecific, Class::Private][class as usize];
        let i = id(class, number, constructed);
        let mut buf = [0u8; 8];
        let n = i.encode(&mut buf).unwrap();
        prop_assert_eq!(n, i.encoded_len());
        prop_assert_eq!(Identifier::decode(&buf[..n], &Config::DER, Rules::Der).unwrap(), (i, n));
    }

    #[test]
    fn header_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..20)) {
        let _ = Header::decode(&bytes, 7, &Config::BER, Rules::Ber);
        let _ = Header::decode(&bytes, 7, &Config::DER, Rules::Der);
    }

    #[test]
    fn header_round_trips(class in 0u8..4, number in 0u32..=16_383, constructed in any::<bool>(), len in 0u64..1_000_000) {
        let class = [Class::Universal, Class::Application, Class::ContextSpecific, Class::Private][class as usize];
        let i = id(class, number, constructed);
        let mut buf = [0u8; 15];
        let a = i.encode(&mut buf).unwrap();
        let b = Length::Definite(len).encode(&mut buf[a..]).unwrap();
        match Header::decode(&buf[..a + b], 100, &Config::DER, Rules::Der) {
            Ok(HeaderParse::Complete(h)) => {
                prop_assert_eq!(h.id(), i);
                prop_assert_eq!(h.length(), Length::Definite(len));
                prop_assert_eq!(h.raw(), &buf[..a + b]);
                prop_assert_eq!(h.offset(), 100);
                prop_assert_eq!(h.content_offset(), 100 + (a + b) as u64);
            }
            // Universal types with a fixed form or DER-constructed strings are rejected.
            Err(e) => prop_assert!(matches!(
                e.kind(),
                ErrorKind::WrongUniversalForm | ErrorKind::ConstructedNotAllowed | ErrorKind::IndefiniteOnPrimitive
            )),
            other => prop_assert!(false, "{other:?}"),
        }
    }
}

#[test]
fn exhaustive_one_and_two_octet_identifiers_and_lengths() {
    for a in 0..=255u8 {
        let r = Identifier::decode(&[a], &Config::BER, Rules::Ber);
        if a & 0x1F == 0x1F {
            assert_eq!(r.unwrap_err().kind(), &ErrorKind::Truncated);
        } else {
            let (i, n) = r.unwrap();
            assert_eq!(n, 1);
            assert_eq!(i.tag.number, u32::from(a & 0x1F));
            assert_eq!(i.constructed, a & 0x20 != 0);
            let mut out = [0u8; 1];
            i.encode(&mut out).unwrap();
            assert_eq!(out[0], a);
        }
        let l = Length::decode(&[a], Rules::Ber);
        match a {
            0xFF => assert_eq!(l.unwrap_err().kind(), &ErrorKind::ReservedLengthOctet),
            0x80 => assert_eq!(l.unwrap(), (Length::Indefinite, 1)),
            0x81..=0xFE => assert_eq!(l.unwrap_err().kind(), &ErrorKind::Truncated),
            _ => assert_eq!(l.unwrap(), (Length::Definite(u64::from(a)), 1)),
        }
        for b in 0..=255u8 {
            let r = Identifier::decode(&[a, b], &Config::BER, Rules::Ber);
            if a & 0x1F == 0x1F {
                match b {
                    0x80 => assert_eq!(r.unwrap_err().kind(), &ErrorKind::NonMinimalBase128),
                    0x81..=0xFF => assert_eq!(r.unwrap_err().kind(), &ErrorKind::Truncated),
                    0..=30 => assert_eq!(r.unwrap_err().kind(), &ErrorKind::HighFormForLowTag),
                    _ => assert_eq!(r.unwrap().0.tag.number, u32::from(b)),
                }
            } else {
                assert_eq!(r.unwrap().1, 1);
            }
            let r = Length::decode(&[a, b], Rules::Ber);
            match a {
                0x81 => assert_eq!(r.unwrap(), (Length::Definite(u64::from(b)), 2)),
                0x82..=0xFE => assert_eq!(r.unwrap_err().kind(), &ErrorKind::Truncated),
                _ => {}
            }
            let r = Length::decode(&[a, b], Rules::Der);
            if a == 0x81 {
                if b < 128 {
                    assert_eq!(r.unwrap_err().kind(), &ErrorKind::NonMinimalLength);
                } else {
                    assert_eq!(r.unwrap(), (Length::Definite(u64::from(b)), 2));
                }
            }
        }
    }
}

#[test]
fn identifier_rules() {
    // High form for a low number is invalid in BER too.
    let e = Identifier::decode(&[0x1F, 0x1E], &Config::BER, Rules::Ber).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::HighFormForLowTag);
    let (i, n) = Identifier::decode(&[0x1F, 0x1F], &Config::BER, Rules::Ber).unwrap();
    assert_eq!((i.tag.number, n), (31, 2));
    let e = Identifier::decode(&[0x1F, 0x80, 0x1F], &Config::BER, Rules::Ber).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::NonMinimalBase128, 1));
    // Above max_tag_number, and above u32.
    let e = Identifier::decode(&[0x1F, 0x81, 0x80, 0x00], &Config::DER, Rules::Der).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::TagNumberTooLarge);
    let e = Identifier::decode(&[0x1F, 0x90, 0x80, 0x80, 0x80, 0x00], &Config::DER, Rules::Der)
        .unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::TagNumberTooLarge);
    let cfg = Config::DER.with_max_tag_number(40);
    assert!(Identifier::decode(&[0x1F, 0x28], &cfg, Rules::Der).is_ok());
    assert!(Identifier::decode(&[0x1F, 0x29], &cfg, Rules::Der).is_err());
    assert_eq!(
        Identifier::decode(&[0x1F, 0x7F], &Config::DER, Rules::Der).unwrap().0.tag.number,
        127
    );
    // Ordering ignores the constructed bit.
    assert!(
        Tag { class: Class::Universal, number: 31 } < Tag { class: Class::Application, number: 0 }
    );
    const { assert!(Tag::SEQUENCE.const_eq(&Tag::universal(16))) };
}

#[test]
fn length_rules() {
    // 0x89 00 .. 05 is a valid 5 in BER.
    let mut long = vec![0x89];
    long.extend([0, 0, 0, 0, 0, 0, 0, 0, 5]);
    assert_eq!(Length::decode(&long, Rules::Ber).unwrap(), (Length::Definite(5), 10));
    assert_eq!(Length::decode(&long, Rules::Der).unwrap_err().kind(), &ErrorKind::NonMinimalLength);
    // Nine significant octets overflow u64.
    let mut over = vec![0x89, 1];
    over.extend([0; 8]);
    assert_eq!(Length::decode(&over, Rules::Ber).unwrap_err().kind(), &ErrorKind::LengthOverflow);
    assert_eq!(
        Length::decode(&[0x80], Rules::Der).unwrap_err().kind(),
        &ErrorKind::IndefiniteNotAllowed
    );
    assert_eq!(
        Length::decode(&[0x82, 0x00, 0x80], Rules::Der).unwrap_err().kind(),
        &ErrorKind::NonMinimalLength
    );
    assert_eq!(
        Length::decode(&[0x82, 0x01, 0x00], Rules::Der).unwrap(),
        (Length::Definite(256), 3)
    );
    let mut out = [0u8; 9];
    assert_eq!(Length::Indefinite.encode(&mut out).unwrap(), 1);
    assert_eq!(out[0], 0x80);
    let e = Length::Definite(300).encode(&mut out[..2]).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::InsufficientSize { required: 3 });
}

fn decode_header<'a>(
    bytes: &'a [u8],
    cfg: &Config,
    rules: Rules,
) -> Result<HeaderParse<'a>, Error> {
    Header::decode(bytes, 0, cfg, rules)
}

fn error_kind(bytes: &[u8], cfg: &Config, rules: Rules) -> ErrorKind {
    decode_header(bytes, cfg, rules).unwrap_err().kind().clone()
}

#[test]
fn header_checks() {
    // Indefinite is fine on constructed values under BER only.
    assert!(matches!(
        decode_header(&[0x30, 0x80], &Config::BER, Rules::Ber),
        Ok(HeaderParse::Complete(_))
    ));
    assert_eq!(
        error_kind(&[0x30, 0x80], &Config::DER, Rules::Der),
        ErrorKind::IndefiniteNotAllowed
    );
    assert_eq!(
        error_kind(&[0x04, 0x80], &Config::BER, Rules::Ber),
        ErrorKind::IndefiniteOnPrimitive
    );
    // Fixed universal forms.
    for tag in [0x10u8, 0x11] {
        assert_eq!(
            error_kind(&[tag, 0x00], &Config::BER, Rules::Ber),
            ErrorKind::WrongUniversalForm
        );
    }
    for tag in [0x01u8, 0x02, 0x05, 0x06, 0x0A, 0x0D] {
        assert_eq!(
            error_kind(&[tag | 0x20, 0x00], &Config::BER, Rules::Ber),
            ErrorKind::WrongUniversalForm
        );
    }
    // Constructed strings are DER-invalid and BER-valid.
    for tag in [0x03u8, 0x04, 0x0C, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1A, 0x1C, 0x1E] {
        assert_eq!(
            error_kind(&[tag | 0x20, 0x00], &Config::DER, Rules::Der),
            ErrorKind::ConstructedNotAllowed
        );
        assert!(decode_header(&[tag | 0x20, 0x00], &Config::BER, Rules::Ber).is_ok());
    }
    // Rules argument overrides config rules.
    assert_eq!(
        error_kind(&[0x24, 0x00], &Config::BER, Rules::Der),
        ErrorKind::ConstructedNotAllowed
    );
    // Length limit.
    let cfg = Config::DER.with_max_value_len(10);
    assert!(decode_header(&[0x04, 0x0A], &cfg, Rules::Der).is_ok());
    let e = decode_header(&[0x04, 0x0B], &cfg, Rules::Der).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::ElementTooLarge, 1));
}

#[test]
fn header_incomplete_and_offsets() {
    let full = [0xBF, 0x82, 0x01, 0x82, 0x01, 0x00];
    for cut in 0..full.len() - 1 {
        let r = Header::decode(&full[..cut], 0, &Config::DER, Rules::Der).unwrap();
        let HeaderParse::Incomplete { at_least } = r else { panic!("{cut}") };
        assert!(at_least > cut && at_least <= full.len(), "{cut} {at_least}");
    }
    let HeaderParse::Complete(h) = Header::decode(&full, 1000, &Config::DER, Rules::Der).unwrap()
    else {
        panic!()
    };
    assert_eq!(h.tag(), Tag { class: Class::ContextSpecific, number: 257 });
    assert!(h.constructed());
    assert_eq!(h.length(), Length::Definite(256));
    assert_eq!((h.offset(), h.content_offset(), h.raw().len()), (1000, 1006, 6));
    // Errors carry absolute offsets.
    let e = Header::decode(&[0x04, 0xFF], 50, &Config::DER, Rules::Der).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::ReservedLengthOctet, 51));
    let e = Header::decode(&[0x04, 0x81, 0x05], 50, &Config::DER, Rules::Der).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::NonMinimalLength, 51));
}

#[test]
fn offsets_near_u64_max_never_panic() {
    let bytes = [0x25, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    for base in [u64::MAX, u64::MAX - 1, u64::MAX - 5] {
        let _ = Header::decode(&bytes, base, &Config::BER, Rules::Ber);
        let _ = Header::decode(&bytes[..2], base, &Config::BER, Rules::Ber);
        let mut r = SliceReader::with_base(&[0x04, 0x01, 0x00], base, &Config::DER);
        let _ = r.read::<OctetString>();
        let mut t = Tokenizer::<4>::new(Config::DER);
        let _ = t.step(&bytes, true);
    }
}
