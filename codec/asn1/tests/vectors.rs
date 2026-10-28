mod common;

use bouncycastle_asn1::*;
use common::{h, hex, leak};

fn dec<'a, T: Decode<'a>>(bytes: &'a [u8], config: &Config) -> Result<T, Error> {
    let mut r = SliceReader::new(bytes, config);
    let v = r.read::<T>()?;
    r.finish()?;
    Ok(v)
}

fn enc<T: Encode>(v: &T) -> Vec<u8> {
    let n = usize::try_from(v.encoded_len().unwrap()).unwrap();
    let mut buf = vec![0u8; n];
    encode_to_slice(v, &mut buf).unwrap().to_vec()
}

/// Valid under both rules; DER re-encodes to identical bytes.
fn both<'a, T: Decode<'a> + Encode + std::fmt::Debug>(bytes: &'a [u8]) -> T {
    let ber = dec::<T>(bytes, &Config::BER).unwrap();
    let der = dec::<T>(bytes, &Config::DER).unwrap();
    assert_eq!(enc(&der), bytes, "re-encoding");
    assert_eq!(enc(&ber), bytes);
    der
}

/// Valid under BER, rejected under DER with `kind`.
fn ber_only<'a, T: Decode<'a> + std::fmt::Debug>(bytes: &'a [u8], kind: ErrorKind) -> T {
    assert_eq!(dec::<T>(bytes, &Config::DER).unwrap_err().kind(), &kind);
    dec::<T>(bytes, &Config::BER).unwrap()
}

fn invalid<'a, T: Decode<'a> + std::fmt::Debug>(bytes: &'a [u8], value_error: ValueError) {
    for config in [Config::BER, Config::DER] {
        let e = dec::<T>(bytes, &config).unwrap_err();
        assert_eq!(e.kind(), &ErrorKind::InvalidValue(value_error.clone()), "{bytes:02X?}");
    }
}

#[test]
fn integers() {
    for (enc_hex, expected) in [
        ("02 01 00", 0i128),
        ("02 01 7F", 127),
        ("02 02 00 80", 128),
        ("02 02 01 00", 256),
        ("02 01 80", -128),
        ("02 02 FF 7F", -129),
    ] {
        let bytes = hex(enc_hex);
        let int = both::<Int>(&bytes);
        assert_eq!(i128::try_from(&int).unwrap(), expected);
        assert_eq!(int.is_negative(), expected < 0);
        assert_eq!(both::<i128>(&bytes), expected);
        assert_eq!(
            both::<Enumerated>(leak([&[0x0A], &bytes[1..]].concat())).as_int().as_bytes(),
            int.as_bytes()
        );
    }
    assert_eq!(Int::new(&[0x00, 0x80]).unwrap().unsigned_bytes().unwrap(), &[0x80]);
    assert_eq!(Int::new(&[0x7F]).unwrap().unsigned_bytes().unwrap(), &[0x7F]);
    assert_eq!(
        Int::new(&[0x80]).unwrap().unsigned_bytes().unwrap_err(),
        ValueError::IntegerOutOfRange
    );
    invalid::<Int>(h("02 00"), ValueError::IntegerEmpty);
    invalid::<Int>(h("02 02 00 7F"), ValueError::IntegerNotMinimal);
    invalid::<Int>(h("02 02 FF 80"), ValueError::IntegerNotMinimal);
    invalid::<Enumerated>(h("0A 00"), ValueError::IntegerEmpty);
}

#[test]
fn native_integer_fields() {
    fn check<'a, T: Decode<'a> + std::fmt::Debug + PartialEq>(
        h: &str,
        expected: Result<T, ValueError>,
    ) {
        let bytes: &'static [u8] = Box::leak(hex(h).into_boxed_slice());
        for config in [Config::BER, Config::DER] {
            match &expected {
                Ok(v) => assert_eq!(&dec::<T>(bytes, &config).unwrap(), v),
                Err(e) => assert_eq!(
                    dec::<T>(bytes, &config).unwrap_err().kind(),
                    &ErrorKind::InvalidValue(e.clone())
                ),
            }
        }
    }
    check::<i8>("02 01 7F", Ok(127));
    check::<i8>("02 01 80", Ok(-128));
    check::<u8>("02 01 80", Err(ValueError::IntegerOutOfRange));
    check::<u8>("02 02 00 FF", Ok(255));
    check::<u8>("02 02 01 00", Err(ValueError::IntegerOutOfRange));
    check::<u64>("02 09 00 FF FF FF FF FF FF FF FF", Ok(u64::MAX));
    check::<i64>("02 09 00 FF FF FF FF FF FF FF FF", Err(ValueError::IntegerOutOfRange));
    assert_eq!(both::<u64>(h("02 09 00 FF FF FF FF FF FF FF FF")), u64::MAX);
    assert_eq!(
        both::<u128>(h("02 11 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF")),
        u128::MAX
    );
    assert_eq!(both::<i128>(leak([&[0x02, 0x10, 0x80], &[0u8; 15][..]].concat())), i128::MIN);
    for v in [0u32, 1, 127, 128, 255, 256, 65_535, 65_536, u32::MAX] {
        let bytes = enc(&v);
        assert_eq!(dec::<u32>(&bytes, &Config::DER).unwrap(), v);
    }
    for v in [0i16, -1, -128, -129, 127, 128, i16::MIN, i16::MAX] {
        let bytes = enc(&v);
        assert_eq!(dec::<i16>(&bytes, &Config::DER).unwrap(), v);
    }
    assert_eq!(enc(&u64::MAX), hex("02 09 00 FF FF FF FF FF FF FF FF"));
    let int = Int::new(&[0x01, 0x00]).unwrap();
    assert_eq!(usize::try_from(&int).unwrap(), 256);
    assert_eq!(isize::try_from(int.clone()).unwrap(), 256);
    assert_eq!(u8::try_from(int).unwrap_err(), ValueError::IntegerOutOfRange);
}

#[test]
fn booleans_and_null() {
    assert!(both::<bool>(h("01 01 FF")));
    assert!(!both::<bool>(h("01 01 00")));
    assert!(ber_only::<bool>(h("01 01 01"), ErrorKind::InvalidValue(ValueError::BooleanNotDer)));
    invalid::<bool>(h("01 00"), ValueError::BooleanLength);
    invalid::<bool>(h("01 02 FF FF"), ValueError::BooleanLength);
    both::<Null>(h("05 00"));
    ber_only::<Null>(h("05 81 00"), ErrorKind::NonMinimalLength);
    invalid::<Null>(h("05 01 00"), ValueError::NullNotEmpty);
}

#[test]
fn object_identifiers() {
    let oid = both::<Oid>(h("06 06 2A 86 48 86 F7 0D"));
    assert_eq!(oid.arcs().collect::<Vec<_>>(), [1, 2, 840, 113549]);
    assert_eq!(oid.to_string(), "1.2.840.113549");
    let rel = both::<RelOid>(h("0D 05 81 FD 59 03 02"));
    assert_eq!(rel.arcs().collect::<Vec<_>>(), [32473, 3, 2]);
    assert_eq!(both::<Oid>(h("06 03 55 04 03")).arcs().collect::<Vec<_>>(), [2, 5, 4, 3]);
    assert_eq!(both::<Oid>(h("06 01 00")).arcs().collect::<Vec<_>>(), [0, 0]);
    assert_eq!(both::<Oid>(h("06 01 50")).arcs().collect::<Vec<_>>(), [2, 0]);
    // UUID arcs under 2.25 need 128 bits.
    let mut buf = [0u8; 32];
    let uuid = Oid::from_arcs(&[2, 25, u128::MAX - 100], &mut buf).unwrap();
    assert_eq!(uuid.arcs().collect::<Vec<_>>(), [2, 25, u128::MAX - 100]);
    invalid::<Oid>(h("06 00"), ValueError::OidEmpty);
    invalid::<Oid>(h("06 03 2A 80 01"), ValueError::OidNotMinimal);
    invalid::<Oid>(h("06 02 2A 86"), ValueError::OidTruncated);
    invalid::<RelOid>(h("0D 00"), ValueError::OidEmpty);
    let mut too_big = vec![0x06, 0x16, 0x2A];
    too_big.extend([
        0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x00,
    ]);
    too_big.truncate(2 + 0x16.min(too_big.len() - 2));
    let len = too_big.len() - 2;
    too_big[1] = len as u8;
    invalid::<Oid>(&too_big, ValueError::OidArcTooLarge);
    // First arc combinations.
    for arcs in [&[3u128, 1][..], &[0, 40], &[1, 40], &[1][..]] {
        let e = Oid::from_arcs(arcs, &mut buf).unwrap_err();
        assert_eq!(e.kind(), &ErrorKind::InvalidValue(ValueError::OidFirstArc));
    }
    assert_eq!(
        Oid::from_arcs(&[], &mut buf).unwrap_err().kind(),
        &ErrorKind::InvalidValue(ValueError::OidEmpty)
    );
    assert!(Oid::from_arcs(&[1, 39, 5], &mut buf).is_ok());
    let e = Oid::from_arcs(&[2, 999, 1_000_000], &mut buf[..2]).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::InsufficientSize { .. }));
    // Equality and hashing are byte comparisons.
    assert_eq!(Oid::new(&[0x2A]).unwrap(), Oid::new(&[0x2A]).unwrap());
    const OID: Oid<'static> = match Oid::new(&[0x55, 0x04, 0x03]) {
        Ok(o) => o,
        Err(_) => panic!(),
    };
    assert_eq!(OID.to_string(), "2.5.4.3");
}

#[test]
fn bit_strings() {
    let bs = both::<BitString>(h("03 04 06 6E 5D C0"));
    assert_eq!((bs.unused_bits(), bs.data(), bs.len_bits()), (6, &[0x6E, 0x5D, 0xC0][..], 18));
    assert_eq!(bs.bit(0), Some(false));
    assert_eq!(bs.bit(1), Some(true));
    assert_eq!(bs.bit(17), Some(true));
    assert_eq!(bs.bit(18), None);
    assert_eq!(bs.ones().count(), 12);
    let padded = ber_only::<BitString>(
        h("03 04 06 6E 5D E0"),
        ErrorKind::InvalidValue(ValueError::BitStringPaddingNotZero),
    );
    assert_eq!(padded.unused_bits(), 6);
    ber_only::<BitString>(h("03 81 04 06 6E 5D C0"), ErrorKind::NonMinimalLength);
    invalid::<BitString>(h("03 00"), ValueError::BitStringUnusedBits);
    invalid::<BitString>(h("03 02 08 00"), ValueError::BitStringUnusedBits);
    invalid::<BitString>(h("03 01 01"), ValueError::BitStringUnusedBits);
    assert_eq!(both::<BitString>(h("03 01 00")).len_bits(), 0);
    // Constructed encodings need the streaming StringReassembler.
    assert_eq!(
        dec::<BitString>(h("23 09 03 03 00 6E 5D 03 02 06 C0"), &Config::BER).unwrap_err().kind(),
        &ErrorKind::ConstructedNotAllowed
    );
    let kb = both::<NamedBits>(h("03 02 07 80"));
    assert!(kb.is_set(0) && !kb.is_set(1));
    assert_eq!(
        dec::<NamedBits>(h("03 02 06 80"), &Config::DER).unwrap_err().kind(),
        &ErrorKind::InvalidValue(ValueError::NamedBitsTrailingZero)
    );
    assert!(dec::<NamedBits>(h("03 02 06 80"), &Config::BER).is_ok());
    assert!(dec::<NamedBits>(h("03 01 00"), &Config::DER).is_ok());
}

#[test]
fn octet_and_character_strings() {
    let os = both::<OctetString>(h("04 08 01 23 45 67 89 AB CD EF"));
    assert_eq!(os.as_bytes(), &[1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    for h in [
        "24 0C 04 04 01 23 45 67 04 04 89 AB CD EF",
        "24 80 04 04 00 00 00 00 04 04 00 00 00 00 00 00",
    ] {
        let bytes = hex(h);
        assert!(dec::<OctetString>(&bytes, &Config::DER).is_err());
        assert_eq!(
            dec::<OctetString>(&bytes, &Config::BER).unwrap_err().kind(),
            &ErrorKind::ConstructedNotAllowed
        );
    }
    assert_eq!(
        both::<Ia5String>(h("16 11 74 65 73 74 31 40 65 78 61 6D 70 6C 65 2E 63 6F 6D")).as_str(),
        "test1@example.com"
    );
    assert_eq!(
        both::<PrintableString>(h("13 0B 54 65 73 74 20 55 73 65 72 20 31")).as_str(),
        "Test User 1"
    );
    assert_eq!(both::<Utf8String>(h("0C 09 ED 95 9C EA B5 AD EC 96 B4")).as_str(), "한국어");
    invalid::<PrintableString>(h("13 01 40"), ValueError::NotInAlphabet);
    invalid::<PrintableString>(h("13 01 2A"), ValueError::NotInAlphabet);
    invalid::<Ia5String>(h("16 01 80"), ValueError::NotInAlphabet);
    invalid::<VisibleString>(h("1A 01 1F"), ValueError::NotInAlphabet);
    invalid::<VisibleString>(h("1A 01 7F"), ValueError::NotInAlphabet);
    invalid::<NumericString>(h("12 01 41"), ValueError::NotInAlphabet);
    assert_eq!(both::<NumericString>(h("12 04 31 20 32 39")).as_str(), "1 29");
    invalid::<Utf8String>(h("0C 02 C3 28"), ValueError::InvalidCharacterEncoding);
    invalid::<Utf8String>(h("0C 03 ED A0 80"), ValueError::InvalidCharacterEncoding);
    let bmp = both::<BmpString>(h("1E 04 00 41 20 AC"));
    assert_eq!(bmp.chars().collect::<Result<String, _>>().unwrap(), "A€");
    invalid::<BmpString>(h("1E 03 00 41 20"), ValueError::InvalidLength);
    invalid::<BmpString>(h("1E 02 D8 00"), ValueError::InvalidCharacterEncoding);
    let uni = both::<UniversalString>(h("1C 08 00 00 00 41 00 01 F6 00"));
    assert_eq!(uni.chars().collect::<Result<String, _>>().unwrap(), "A\u{1F600}");
    invalid::<UniversalString>(h("1C 06 00 00 00 41 00 00"), ValueError::InvalidLength);
    invalid::<UniversalString>(h("1C 04 00 11 00 00"), ValueError::InvalidCharacterEncoding);
    invalid::<UniversalString>(h("1C 04 00 00 D8 00"), ValueError::InvalidCharacterEncoding);
    assert_eq!(both::<TeletexString>(h("14 03 FF 00 80")).as_bytes(), &[0xFF, 0, 0x80]);
}

fn check_utc(hx: &str, expected: Option<(u16, u8, u8, u8, u8, u8)>) {
    let bytes = hex(hx);
    for config in [Config::BER, Config::DER] {
        match (dec::<UtcTime>(&bytes, &config), expected) {
            (Ok(t), Some(e)) => assert_eq!((t.year, t.month, t.day, t.hour, t.minute, t.second), e),
            (Err(e), None) => {
                assert_eq!(e.kind(), &ErrorKind::InvalidValue(ValueError::InvalidTime))
            }
            (got, want) => panic!("{hx}: {got:?} vs {want:?}"),
        }
    }
    if expected.is_some() {
        assert_eq!(enc(&dec::<UtcTime>(&bytes, &Config::DER).unwrap()), bytes);
    }
}

#[test]
fn times() {
    let t = both::<UtcTime>(h("17 0D 39 31 30 35 30 36 32 33 34 35 34 30 5A"));
    assert_eq!((t.year, t.month, t.day, t.hour, t.minute, t.second), (1991, 5, 6, 23, 45, 40));
    let g = both::<GeneralizedTime>(h("18 0F 39 39 39 39 31 32 33 31 32 33 35 39 35 39 5A"));
    assert_eq!(
        (g.year, g.month, g.day, g.hour, g.minute, g.second, g.nanos),
        (9999, 12, 31, 23, 59, 59, 0)
    );
    // Years and day ranges.
    check_utc("17 0D 30 30 30 32 32 39 30 30 30 30 30 30 5A", Some((2000, 2, 29, 0, 0, 0)));
    check_utc("17 0D 39 36 30 32 32 39 30 30 30 30 30 30 5A", Some((1996, 2, 29, 0, 0, 0)));
    check_utc("17 0D 39 37 30 32 32 39 30 30 30 30 30 30 5A", None);
    check_utc("17 0D 35 30 30 31 30 31 30 30 30 30 30 30 5A", Some((1950, 1, 1, 0, 0, 0)));
    check_utc("17 0D 34 39 31 32 33 31 32 33 35 39 35 39 5A", Some((2049, 12, 31, 23, 59, 59)));
    for (h, ok) in [
        ("18 0F 32 30 30 30 30 32 32 39 30 30 30 30 30 30 5A", true),
        ("18 0F 31 39 30 30 30 32 32 39 30 30 30 30 30 30 5A", false),
        ("18 0F 32 30 32 34 30 34 33 31 30 30 30 30 30 30 5A", false),
    ] {
        for config in [Config::BER, Config::DER] {
            let r = dec::<GeneralizedTime>(&hex(h), &config);
            assert_eq!(r.is_ok(), ok, "{h}");
            if let Err(e) = r {
                assert_eq!(e.kind(), &ErrorKind::InvalidValue(ValueError::InvalidTime));
            }
        }
    }
    // Hour 24, second 60, month 13, day 0.
    for h in [
        "17 0D 39 31 30 35 30 36 32 34 30 30 30 30 5A",
        "17 0D 39 31 30 35 30 36 32 33 35 39 36 30 5A",
        "17 0D 39 31 31 33 30 36 32 33 34 35 34 30 5A",
        "17 0D 39 31 30 35 30 30 32 33 34 35 34 30 5A",
    ] {
        check_utc(h, None);
    }
    // Fractions in DER: no trailing zeros, at most nine digits.
    let frac =
        both::<GeneralizedTime>(h("18 12 32 30 32 30 30 31 30 31 30 30 30 30 30 30 2E 35 31 5A"));
    assert_eq!(frac.nanos, 510_000_000);
    let bytes = hex("18 12 32 30 32 30 30 31 30 31 30 30 30 30 30 30 2E 35 30 5A");
    assert!(dec::<GeneralizedTime>(&bytes, &Config::DER).is_err());
    let nine =
        hex("18 19 32 30 32 30 30 31 30 31 30 30 30 30 30 30 2E 31 32 33 34 35 36 37 38 39 5A");
    assert_eq!(both::<GeneralizedTime>(&nine).nanos, 123_456_789);
    let ten =
        hex("18 1A 32 30 32 30 30 31 30 31 30 30 30 30 30 30 2E 31 32 33 34 35 36 37 38 39 31 5A");
    for config in [Config::BER, Config::DER] {
        assert_eq!(
            dec::<GeneralizedTime>(&ten, &config).unwrap_err().kind(),
            &ErrorKind::InvalidValue(ValueError::InvalidTime)
        );
    }
}

#[cfg(not(feature = "ber-time"))]
#[test]
fn ber_time_forms_need_the_feature() {
    let bytes = hex("17 11 39 31 30 35 30 36 31 36 34 35 34 30 2D 30 37 30 30");
    for config in [Config::BER, Config::DER] {
        assert_eq!(
            dec::<UtcTime>(&bytes, &config).unwrap_err().kind(),
            &ErrorKind::InvalidValue(ValueError::InvalidTime)
        );
    }
}

#[cfg(feature = "ber-time")]
#[test]
fn ber_time_forms() {
    let bytes = hex("17 11 39 31 30 35 30 36 31 36 34 35 34 30 2D 30 37 30 30");
    let t = ber_only::<UtcTime>(&bytes, ErrorKind::InvalidValue(ValueError::InvalidTime));
    assert_eq!((t.hour, t.minute, t.second, t.utc_offset_minutes), (16, 45, 40, Some(-420)));
    let t = dec::<UtcTime>(h("17 0B 39 31 30 35 30 36 32 33 34 35 5A"), &Config::BER).unwrap();
    assert_eq!((t.minute, t.second), (45, 0));
    let t = dec::<UtcTime>(h("17 0F 39 31 30 35 30 36 32 33 34 35 2B 30 31 33 30"), &Config::BER)
        .unwrap();
    assert_eq!(t.utc_offset_minutes, Some(90));
    let g = |s: &str| {
        let mut v = vec![0x18, s.len() as u8];
        v.extend(s.bytes());
        dec::<GeneralizedTime>(&v, &Config::BER)
    };
    let t = g("2020010112Z").unwrap();
    assert_eq!((t.hour, t.minute, t.second), (12, 0, 0));
    let t = g("2020010112.5Z").unwrap();
    assert_eq!((t.hour, t.minute, t.second, t.nanos), (12, 30, 0, 0));
    let t = g("202001011230,25").unwrap();
    assert_eq!((t.minute, t.second, t.local), (30, 15, true));
    let t = g("20200101123045.123456789+0530").unwrap();
    assert_eq!((t.nanos, t.utc_offset_minutes, t.local), (123_456_789, Some(330), false));
    let t = g("2020010112-05").unwrap();
    assert_eq!(t.utc_offset_minutes, Some(-300));
    assert!(g("2020010124Z").is_err());
    assert!(g("20200101123045.1234567891Z").is_err());
    assert!(g("20200101123045.Z").is_err());
    assert!(g("2020010112+2400").is_err());
    assert!(g("20200230123045Z").is_err());
    assert!(g("20200101123045Zjunk").is_err());
    // DER still rejects them.
    assert!(
        dec::<GeneralizedTime>(
            &[0x18, 0x0B, b'2', b'0', b'2', b'0', b'0', b'1', b'0', b'1', b'1', b'2', b'Z'],
            &Config::DER
        )
        .is_err()
    );
}

#[test]
fn constructed_times_decode_by_copying_segments() {
    // UTCTime 910506234540Z split over two OCTET-STRING-like UTCTime segments.
    let bytes = hex("37 80 17 04 39 31 30 35 17 09 30 36 32 33 34 35 34 30 5A 00 00");
    let t = dec::<UtcTime>(&bytes, &Config::BER).unwrap();
    assert_eq!((t.year, t.month, t.second), (1991, 5, 40));
    assert_eq!(
        dec::<UtcTime>(&bytes, &Config::DER).unwrap_err().kind(),
        &ErrorKind::ConstructedNotAllowed
    );
}

#[test]
fn error_offsets_are_absolute() {
    let bytes = hex("30 06 02 01 00 02 01 80");
    let mut r = SliceReader::with_base(&bytes, 1000, &Config::DER);
    let e = r.read_sequence(|s| {
        assert_eq!(s.read::<u8>()?, 0);
        s.read::<u8>()
    });
    let e = e.unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (&ErrorKind::InvalidValue(ValueError::IntegerOutOfRange), 1007)
    );
}

#[test]
fn size_and_range_traits_use_characters() {
    let s = Utf8String::new("한국어");
    assert_eq!(s.constraint_size(), 3);
    assert_eq!(BitString::new(6, &[0, 0, 0]).unwrap().constraint_size(), 18);
}
