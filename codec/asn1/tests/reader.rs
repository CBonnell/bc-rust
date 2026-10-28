mod common;

use bouncycastle_asn1::*;
use common::{h, hex, leak};
use proptest::prelude::*;

#[derive(Debug, PartialEq)]
struct Atv<'a> {
    oid: Oid<'a>,
    value: Any<'a>,
}

impl FixedTag for Atv<'_> {
    const TAG: Tag = Tag::SEQUENCE;
    const CONSTRUCTED: bool = true;
}

impl<'a> DecodeValue<'a> for Atv<'a> {
    fn decode_value(_: &Header<'a>, c: &mut SliceReader<'a>) -> Result<Self, Error> {
        Ok(Atv { oid: c.read()?, value: c.read()? })
    }
}

impl EncodeValue for Atv<'_> {
    fn value_len(&self) -> Result<u64, Error> {
        Ok(self.oid.encoded_len()? + self.value.encoded_len()?)
    }
    fn encode_value(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.oid.encode(w)?;
        self.value.encode(w)
    }
}

type Rdn<'a> = SetOf<'a, Atv<'a>>;
type Name<'a> = SequenceOf<'a, Rdn<'a>>;

const NAME_DER: &str = "30 35 31 0B 30 09 06 03 55 04 06 13 02 55 53
      31 15 30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E
      31 0F 30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31";
const NAME_UNSORTED: &str = "30 33 31 0B 30 09 06 03 55 04 06 13 02 55 53
      31 24 30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E
            30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31";
const NAME_SORTED: &str = "30 33 31 0B 30 09 06 03 55 04 06 13 02 55 53
      31 24 30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31
            30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E";

fn dec<'a, T: Decode<'a>>(bytes: &'a [u8], config: &Config) -> Result<T, Error> {
    let mut r = SliceReader::new(bytes, config);
    let v = r.read::<T>()?;
    r.finish()?;
    Ok(v)
}

fn enc<T: Encode>(v: &T) -> Vec<u8> {
    let mut buf = vec![0u8; usize::try_from(v.encoded_len().unwrap()).unwrap()];
    encode_to_slice(v, &mut buf).unwrap().to_vec()
}

fn atv_values(name: &Name<'_>) -> Vec<Vec<u8>> {
    name.iter()
        .flat_map(|rdn| {
            rdn.unwrap().iter().map(|a| a.unwrap().value.contents().to_vec()).collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn name_der_decodes_and_reencodes() {
    let bytes = leak(hex(NAME_DER));
    for config in [Config::DER, Config::BER] {
        let name = dec::<Name>(bytes, &config).unwrap();
        assert_eq!(name.len(), 3);
        assert_eq!(
            atv_values(&name),
            [b"US".to_vec(), b"Example Inc.".to_vec(), b"User 1".to_vec()]
        );
    }
    let name = dec::<Name>(bytes, &Config::DER).unwrap();
    assert_eq!(enc(&name), bytes);
}

const RDN_UNSORTED: &str = "31 24 30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E
            30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31";

#[test]
fn name_multivalued_rdn_ordering() {
    let unsorted = leak(hex(NAME_UNSORTED));
    // Elements are decoded as they are reached, so the inner SET OF is checked then.
    let name = dec::<Name>(unsorted, &Config::DER).unwrap();
    let e = name.iter().collect::<Result<Vec<_>, _>>().unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::SetOfNotSorted, 38));
    let name = dec::<Name>(unsorted, &Config::BER).unwrap();
    assert_eq!(name.iter().collect::<Result<Vec<_>, _>>().unwrap().len(), 2);
    let sorted = leak(hex(NAME_SORTED));
    let name = dec::<Name>(sorted, &Config::DER).unwrap();
    assert_eq!(name.iter().collect::<Result<Vec<_>, _>>().unwrap().len(), 2);
    assert_eq!(enc(&name), sorted);
    // Re-encoding an unsorted BER SET OF never silently reorders.
    let name = dec::<Name>(unsorted, &Config::BER).unwrap();
    let mut buf = [0u8; 128];
    assert_eq!(encode_to_slice(&name, &mut buf).unwrap_err().kind(), &ErrorKind::SetOfNotSorted);
    let rdn = leak(hex(RDN_UNSORTED));
    let e = dec::<Rdn>(rdn, &Config::DER).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::SetOfNotSorted, 23));
}

#[test]
fn unsorted_set_of_tolerance_is_field_scoped_and_reported() {
    let rdn = leak(hex(RDN_UNSORTED));
    let tolerant = Config::DER.with_tolerances(Tolerances::NONE.with(Tolerance::UnsortedSetOf));
    // The config alone doesn't tolerate: the field has to opt in.
    assert_eq!(dec::<Rdn>(rdn, &tolerant).unwrap_err().kind(), &ErrorKind::SetOfNotSorted);
    let mut r = SliceReader::new(rdn, &tolerant);
    let set = r.with_tolerance(Tolerance::UnsortedSetOf, |r| r.read::<Rdn>()).unwrap();
    assert!(r.deviations().contains(Tolerance::UnsortedSetOf));
    assert!(!r.deviations().contains(Tolerance::EncodedDefault));
    assert_eq!(r.deviations().iter().collect::<Vec<_>>(), [Tolerance::UnsortedSetOf]);
    assert_eq!(set.len(), 2);
    // The field opts in, the config does not.
    let mut r = SliceReader::new(rdn, &Config::DER);
    assert!(r.with_tolerance(Tolerance::UnsortedSetOf, |r| r.read::<Rdn>()).is_err());
    // Valid input reports nothing.
    let sorted_rdn = leak(hex("31 24 30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31
            30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E"));
    let mut r = SliceReader::new(sorted_rdn, &tolerant);
    r.with_tolerance(Tolerance::UnsortedSetOf, |r| r.read::<Rdn>()).unwrap();
    assert!(r.deviations().is_empty());
    // Lazily decoded nested sets carry the tolerance with them and report on the iterator.
    let name = leak(hex(NAME_UNSORTED));
    let mut r = SliceReader::new(name, &tolerant);
    let name = r.with_tolerance(Tolerance::UnsortedSetOf, |r| r.read::<Name>()).unwrap();
    let mut it = name.iter();
    let items = it.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(items.len(), 2);
    assert!(it.deviations().contains(Tolerance::UnsortedSetOf));
}

#[test]
fn sort_and_encode_set_of() {
    let a = Int::new(&[0x05]).unwrap();
    let b = Int::new(&[0x01, 0x00]).unwrap();
    let c = Int::new(&[0x7F]).unwrap();
    // 02 01 05 < 02 01 7F < 02 02 01 00 as encodings.
    let mut items = [b.clone(), c.clone(), a.clone()];
    let mut scratch = [0u8; 8];
    sort_der_set_of(&mut items, &mut scratch).unwrap();
    assert_eq!(items, [a.clone(), c.clone(), b.clone()]);
    assert_eq!(enc(&SetOfRef(&items)), hex("31 0A 02 01 05 02 01 7F 02 02 01 00"));
    let unsorted = [b, a, c];
    let mut buf = [0u8; 16];
    assert_eq!(
        encode_to_slice(&SetOfRef(&unsorted), &mut buf).unwrap_err().kind(),
        &ErrorKind::SetOfNotSorted
    );
    let mut tiny = [0u8; 5];
    let mut items = unsorted.clone();
    assert!(matches!(
        sort_der_set_of(&mut items, &mut tiny).unwrap_err().kind(),
        ErrorKind::InsufficientSize { required: 8 }
    ));
    assert_eq!(items, unsorted);
    // A shorter encoding sorts before a longer one it prefixes.
    let mut octets = [OctetString::new(&[1, 2]), OctetString::new(&[1])];
    let mut scratch = [0u8; 16];
    sort_der_set_of(&mut octets, &mut scratch).unwrap();
    assert_eq!(octets[0].as_bytes(), &[1]);
}

#[test]
fn sequence_reading() {
    let bytes = leak(hex("30 0B 02 01 07 A0 03 02 01 05 04 01 AA"));
    let mut r = SliceReader::new(bytes, &Config::DER);
    assert_eq!(r.peek_tag().unwrap(), Some(Tag::SEQUENCE));
    let (version, explicit, octets) = r
        .read_sequence(|s| {
            let version: u8 = s.read()?;
            let explicit = s.read_optional::<Explicit<0, u8>>()?;
            let missing = s.read_optional::<Explicit<1, u8>>()?;
            assert!(missing.is_none());
            let octets: OctetString = s.read()?;
            Ok((version, explicit, octets))
        })
        .unwrap();
    assert_eq!((version, explicit.map(|e| e.0), octets.as_bytes()), (7, Some(5), &[0xAA][..]));
    assert_eq!(r.peek_tag().unwrap(), None);
    r.finish().unwrap();
}

#[test]
fn trailing_data_and_wrong_tags() {
    let bytes = leak(hex("30 06 02 01 07 02 01 08"));
    let mut r = SliceReader::new(bytes, &Config::DER);
    let e = r.read_sequence(|s| s.read::<u8>()).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::TrailingData, 5));
    let mut r = SliceReader::new(bytes, &Config::DER);
    let e = r.read::<Int>().unwrap_err();
    assert_eq!(
        e.kind(),
        &ErrorKind::UnexpectedTag { expected: Some(Tag::INTEGER), found: Tag::SEQUENCE }
    );
    let two = leak(hex("05 00 05 00"));
    let mut r = SliceReader::new(two, &Config::DER);
    r.read::<Null>().unwrap();
    assert_eq!(r.finish().unwrap_err().kind(), &ErrorKind::TrailingData);
    let mut r = SliceReader::new(two, &Config::DER);
    r.read::<Null>().unwrap();
    r.read::<Null>().unwrap();
    assert_eq!(r.read::<Null>().unwrap_err().kind(), &ErrorKind::Truncated);
    // Missing field inside a sequence.
    let mut r = SliceReader::new(leak(hex("30 00")), &Config::DER);
    assert_eq!(r.read_sequence(|s| s.read::<u8>()).unwrap_err().kind(), &ErrorKind::Truncated);
}

fn walk(r: &mut SliceReader<'_>) -> Result<(), Error> {
    r.read_tlv_with(None, |header, contents| {
        if header.constructed() {
            while !contents.is_empty() {
                walk(contents)?;
            }
        } else {
            contents.read_contents()?;
        }
        Ok(())
    })
}

#[test]
fn truncation_follows_the_tokenizer() {
    for (data, kind, offset) in [
        ("04 05 01 02", ErrorKind::Truncated, 4),
        ("30 04 02 01", ErrorKind::Truncated, 4),
        ("30 04 02 03 01", ErrorKind::ChildOverrunsParent, 2),
        ("30 01 04 05", ErrorKind::ChildOverrunsParent, 2),
        ("04 82 01", ErrorKind::Truncated, 3),
        ("30 80 05 00", ErrorKind::Truncated, 4),
        ("30 09 04 01 AA 04 05 01", ErrorKind::ChildOverrunsParent, 5),
        ("30 09 04 01 AA 04 03 01", ErrorKind::Truncated, 8),
        ("30 80 30 03 04 05 00 00 00", ErrorKind::ChildOverrunsParent, 4),
    ] {
        let bytes = leak(hex(data));
        let mut r = SliceReader::new(bytes, &Config::BER);
        let e = walk(&mut r).unwrap_err();
        assert_eq!((e.kind(), e.offset()), (&kind, offset), "{data}");
    }
    // Any only checks the value it reads.
    let mut r = SliceReader::new(leak(hex("30 04 02 03 01")), &Config::BER);
    assert_eq!(r.read::<Any>().unwrap_err().kind(), &ErrorKind::Truncated);
}

#[test]
fn indefinite_lengths() {
    let bytes = leak(hex("30 80 02 01 05 24 80 04 01 AA 00 00 00 00"));
    let mut r = SliceReader::new(bytes, &Config::BER);
    let n = r
        .read_sequence(|s| {
            let n: u8 = s.read()?;
            let any: Any = s.read()?;
            assert_eq!(any.tag(), Tag::OCTET_STRING);
            assert!(any.constructed());
            assert_eq!(any.contents(), &hex("04 01 AA")[..]);
            assert_eq!(any.raw(), &hex("24 80 04 01 AA 00 00")[..]);
            Ok(n)
        })
        .unwrap();
    assert_eq!(n, 5);
    r.finish().unwrap();
    assert_eq!(
        dec::<Any>(bytes, &Config::DER).unwrap_err().kind(),
        &ErrorKind::IndefiniteNotAllowed
    );
    // Errors inside an indefinite value are found when it is read.
    let bad = leak(hex("30 80 04 05 01 00 00"));
    assert!(SliceReader::new(bad, &Config::BER).read::<Any>().is_err());
    // An indefinite child must close inside a definite parent.
    let overrun = leak(hex("30 04 30 80 05 00 00 00"));
    let e = SliceReader::new(overrun, &Config::BER)
        .read_sequence(|s| s.read::<Any>().map(drop))
        .unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::ChildOverrunsParent);
}

#[test]
fn eoc_and_depth() {
    let e = SliceReader::new(leak(hex("00 00")), &Config::BER).read::<Any>().unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::UnexpectedEoc, 0));
    let mut data = Vec::new();
    for _ in 0..40 {
        data.extend([0x30, 0x80]);
    }
    for _ in 0..40 {
        data.extend([0, 0]);
    }
    let e = SliceReader::new(leak(data.clone()), &Config::BER).read::<Any>().unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DepthExceeded);
    let mut ok = Vec::new();
    for _ in 0..32 {
        ok.extend([0x30, 0x80]);
    }
    for _ in 0..32 {
        ok.extend([0, 0]);
    }
    assert!(SliceReader::new(leak(ok), &Config::BER).read::<Any>().is_ok());
}

#[test]
fn explicit_implicit_and_choice_style_dispatch() {
    let bytes = leak(hex("A1 03 02 01 05 82 01 AA A3 03 04 01 BB"));
    let mut r = SliceReader::new(bytes, &Config::DER);
    assert_eq!(r.read::<Explicit<1, u8>>().unwrap().0, 5);
    assert_eq!(r.read::<Implicit<2, OctetString>>().unwrap().0.as_bytes(), &[0xAA]);
    // Implicit tagging replaces the tag; a constructed form for a primitive type is rejected.
    assert_eq!(
        r.read::<Implicit<3, OctetString>>().unwrap_err().kind(),
        &ErrorKind::ConstructedNotAllowed
    );
    let mut r = SliceReader::new(bytes, &Config::DER);
    assert!(Explicit::<2, u8>::matches_tag(Tag::context(2)));
    assert!(!Explicit::<2, u8>::matches_tag(Tag::context(1)));
    assert!(r.read_optional::<Implicit<7, u8>>().unwrap().is_none());
    assert_eq!(enc(&Explicit::<1, u8>(5)), hex("A1 03 02 01 05"));
    assert_eq!(enc(&Implicit::<2, OctetString>(OctetString::new(&[0xAA]))), hex("82 01 AA"));
    // Explicit needs the constructed form.
    let e = dec::<Explicit<1, u8>>(h("81 01 05"), &Config::DER).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::WrongUniversalForm);
}

#[test]
fn with_raw_and_read_with_raw() {
    let bytes = leak(hex("30 06 02 01 05 04 01 AA"));
    let mut r = SliceReader::new(bytes, &Config::DER);
    let (raw, inner) = r
        .read_with_raw(|r| {
            r.read_sequence(|s| Ok((s.read::<u8>()?, s.read::<OctetString>()?.as_bytes().len())))
        })
        .unwrap();
    assert_eq!((raw, inner), (bytes, (5, 1)));
    let w = dec::<WithRaw<u8>>(h("02 01 05"), &Config::DER).unwrap();
    assert_eq!((w.value, w.raw), (5, h("02 01 05")));
    assert_eq!(enc(&w), hex("02 01 05"));
}

#[test]
fn tighten_rules_on_reader() {
    // BER outer, DER inner: a non-minimal length inside the tightened subtree fails.
    let bytes = leak(hex("30 80 31 03 04 81 00 00 00"));
    let mut r = SliceReader::new(bytes, &Config::BER);
    r.read_sequence(|s| s.read_set(|set| set.read::<Any>().map(drop))).unwrap();
    let mut r = SliceReader::new(bytes, &Config::BER);
    let e = r
        .read_sequence(|s| {
            s.tighten_rules(Rules::Der, |s| s.read_set(|set| set.read::<Any>().map(drop)))
        })
        .unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::NonMinimalLength);
    // The rules revert afterwards.
    let mut r = SliceReader::new(leak(hex("04 81 00")), &Config::BER);
    r.tighten_rules(Rules::Der, |_| Ok(())).unwrap();
    assert!(r.read::<OctetString>().is_ok());
    let mut r = SliceReader::new(&[], &Config::DER);
    assert_eq!(
        r.tighten_rules(Rules::Ber, |_| Ok(())).unwrap_err().kind(),
        &ErrorKind::RulesLoosened
    );
}

#[test]
fn unknown_trailing_components() {
    let bytes = leak(hex("30 0C 02 01 01 02 01 02 80 00 24 80 00 00"));
    let mut r = SliceReader::new(bytes, &Config::BER);
    let unknown = r
        .read_sequence(|s| {
            assert_eq!(s.read::<u8>()?, 1);
            s.read_unknown()
        })
        .unwrap();
    let tags: Vec<_> = unknown.iter().map(|a| a.unwrap().tag()).collect();
    assert_eq!(tags, [Tag::INTEGER, Tag::context(0), Tag::OCTET_STRING]);
    assert!(!unknown.is_empty());
    // Malformed unknown components are rejected up front.
    let bad = leak(hex("30 05 02 01 01 04 05"));
    let e = SliceReader::new(bad, &Config::BER)
        .read_sequence(|s| {
            s.read::<u8>()?;
            s.skip_remaining()
        })
        .unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::ChildOverrunsParent);
}

#[test]
fn containing_decodes_nested_der() {
    let bytes = leak(hex("04 03 02 01 05"));
    let c = dec::<Containing<u8>>(bytes, &Config::DER).unwrap();
    assert_eq!((*c.value(), c.raw()), (5, &[2, 1, 5][..]));
    assert_eq!(enc(&c), bytes);
    assert!(dec::<Containing<u8>>(h("04 04 02 01 05 00"), &Config::DER).is_err());
}

struct Defined;
impl DefinedBySet for Defined {
    fn decode_defined<'a>(id: &Oid<'_>, value: Any<'a>) -> Result<Option<Self>, Error> {
        if id.as_bytes() == [0x2A] && value.tag() == Tag::NULL {
            Ok(Some(Defined))
        } else {
            Ok(None)
        }
    }
}

#[test]
fn defined_by_set() {
    let oid = Oid::new(&[0x2A]).unwrap();
    let any = dec::<Any>(h("05 00"), &Config::DER).unwrap();
    assert!(Defined::decode_defined(&oid, any.clone()).unwrap().is_some());
    let other = Oid::new(&[0x2B]).unwrap();
    assert!(Defined::decode_defined(&other, any).unwrap().is_none());
}

#[test]
fn any_reencodes_minimally() {
    let any = dec::<Any>(h("04 81 02 AA BB"), &Config::BER).unwrap();
    assert_eq!(enc(&any), hex("04 02 AA BB"));
    let der = dec::<Any>(h("30 03 04 01 AA"), &Config::DER).unwrap();
    assert_eq!(enc(&der), hex("30 03 04 01 AA"));
}

#[test]
fn tag_list_distinctness() {
    const A: TagList = <u8 as StaticTags>::TAGS;
    const B: TagList = <OctetString as StaticTags>::TAGS;
    const BOTH: TagList = A.extend(&B);
    const OK: bool = TagList::all_distinct(&[&A, &B]);
    const DUP: bool = TagList::all_distinct(&[&A, &BOTH]);
    const { assert!(OK) };
    const { assert!(!DUP) };
    assert!(<Any as StaticTags>::TAGS.is_empty());
    assert_eq!(BOTH.len(), 2);
    assert!(BOTH.contains(&Tag::INTEGER));
}

fn codec_round_trip<'a, T: ContentCodec<'a>>(bytes: &'a [u8]) -> Result<(), TestCaseError> {
    if let Ok(value) = T::decode_content(bytes, Rules::Der) {
        let mut out = vec![0u8; bytes.len() + 4];
        prop_assert_eq!(value.content_len(), bytes.len());
        let n = value.encode_content(&mut out).unwrap();
        prop_assert_eq!(&out[..n], bytes);
        prop_assert_eq!(n, bytes.len());
        if !bytes.is_empty() {
            let mut small = vec![0u8; bytes.len() - 1];
            let e = value.encode_content(&mut small).unwrap_err();
            let insufficient = matches!(e.kind(), ErrorKind::InsufficientSize { .. });
            prop_assert!(insufficient);
        }
    }
    let _ = T::decode_content(bytes, Rules::Ber);
    Ok(())
}

fn ascii_like() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(prop_oneof![0x20u8..0x7F, any::<u8>()], 0..24)
}

proptest! {
    #[test]
    fn every_codec_round_trips_in_der(bytes in proptest::collection::vec(any::<u8>(), 0..24), text in ascii_like()) {
        codec_round_trip::<bool>(&bytes)?;
        codec_round_trip::<Int>(&bytes)?;
        codec_round_trip::<Enumerated>(&bytes)?;
        codec_round_trip::<Null>(&bytes)?;
        codec_round_trip::<Oid>(&bytes)?;
        codec_round_trip::<RelOid>(&bytes)?;
        codec_round_trip::<BitString>(&bytes)?;
        codec_round_trip::<NamedBits>(&bytes)?;
        codec_round_trip::<OctetString>(&bytes)?;
        codec_round_trip::<TeletexString>(&bytes)?;
        codec_round_trip::<BmpString>(&bytes)?;
        codec_round_trip::<UniversalString>(&bytes)?;
        codec_round_trip::<UtcTime>(&bytes)?;
        codec_round_trip::<GeneralizedTime>(&bytes)?;
        for t in [&bytes, &text] {
            codec_round_trip::<Utf8String>(t)?;
            codec_round_trip::<PrintableString>(t)?;
            codec_round_trip::<Ia5String>(t)?;
            codec_round_trip::<VisibleString>(t)?;
            codec_round_trip::<NumericString>(t)?;
        }
        codec_round_trip::<i8>(&bytes)?;
        codec_round_trip::<i16>(&bytes)?;
        codec_round_trip::<i32>(&bytes)?;
        codec_round_trip::<i64>(&bytes)?;
        codec_round_trip::<i128>(&bytes)?;
        codec_round_trip::<u8>(&bytes)?;
        codec_round_trip::<u16>(&bytes)?;
        codec_round_trip::<u32>(&bytes)?;
        codec_round_trip::<u64>(&bytes)?;
        codec_round_trip::<u128>(&bytes)?;
    }

    #[test]
    fn native_integers_round_trip(a in any::<i128>(), b in any::<u128>(), c in any::<i64>(), d in any::<u64>()) {
        prop_assert_eq!(dec::<i128>(&enc(&a), &Config::DER).unwrap(), a);
        prop_assert_eq!(dec::<u128>(&enc(&b), &Config::DER).unwrap(), b);
        prop_assert_eq!(dec::<i64>(&enc(&c), &Config::DER).unwrap(), c);
        prop_assert_eq!(dec::<u64>(&enc(&d), &Config::DER).unwrap(), d);
        // Every native encoding is also a valid Int that converts back.
        let bytes = enc(&a);
        let int = dec::<Int>(&bytes, &Config::DER).unwrap();
        prop_assert_eq!(i128::try_from(&int).unwrap(), a);
        prop_assert_eq!(int.is_negative(), a < 0);
    }

    #[test]
    fn reader_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..48)) {
        for config in [Config::BER, Config::DER] {
            let mut r = SliceReader::new(&bytes, &config);
            let _ = r.read::<Any>();
            let mut r = SliceReader::new(&bytes, &config);
            let _ = r.read_sequence(|s| { while !s.is_empty() { s.read::<Any>()?; } Ok(()) });
            let _ = SliceReader::new(&bytes, &config).read::<Name>();
            let _ = SliceReader::new(&bytes, &config).read::<BitString>();
            let _ = SliceReader::new(&bytes, &config).read::<UtcTime>();
            let _ = SliceReader::new(&bytes, &config).read::<u64>();
            let mut r = SliceReader::new(&bytes, &config);
            let _ = r.read_unknown();
        }
    }
}
