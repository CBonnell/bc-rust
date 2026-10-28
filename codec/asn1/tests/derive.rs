mod common;

use bouncycastle_asn1::*;
use bouncycastle_asn1_derive::{Asn1, oid};
use common::{h, hex, leak};

fn dec<'a, T: Decode<'a>>(bytes: &'a [u8], config: &Config) -> Result<T, Error> {
    let mut r = SliceReader::new(bytes, config);
    let v = r.read::<T>()?;
    r.finish()?;
    Ok(v)
}

fn enc<T: Encode>(v: &T) -> Result<Vec<u8>, Error> {
    let n = usize::try_from(v.encoded_len()?).unwrap();
    let mut buf = vec![0u8; n];
    encode_to_slice(v, &mut buf).map(<[u8]>::to_vec)
}

fn kind<T: std::fmt::Debug>(r: Result<T, Error>) -> (ErrorKind, u64) {
    let e = r.unwrap_err();
    (e.kind().clone(), e.offset())
}

// --- Name ---------------------------------------------------------------------------------

#[derive(Asn1, Debug, PartialEq)]
struct AttributeTypeAndValue<'a> {
    oid: Oid<'a>,
    value: Any<'a>,
}

#[derive(Asn1, Debug)]
#[asn1(transparent)]
struct RelativeDistinguishedName<'a>(SetOf<'a, AttributeTypeAndValue<'a>>);

#[derive(Asn1, Debug)]
#[asn1(transparent)]
struct Name<'a>(SequenceOf<'a, RelativeDistinguishedName<'a>>);

const NAME_DER: &str = "30 35 31 0B 30 09 06 03 55 04 06 13 02 55 53
      31 15 30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E
      31 0F 30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31";
const NAME_UNSORTED: &str = "30 33 31 0B 30 09 06 03 55 04 06 13 02 55 53
      31 24 30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E
            30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31";
const NAME_SORTED: &str = "30 33 31 0B 30 09 06 03 55 04 06 13 02 55 53
      31 24 30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31
            30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E";

fn rdn_sizes(name: &Name<'_>) -> Result<Vec<usize>, Error> {
    name.0.iter().map(|rdn| Ok(rdn?.0.len())).collect()
}

#[test]
fn name_vectors() {
    let der = leak(hex(NAME_DER));
    for config in [Config::DER, Config::BER] {
        let name = dec::<Name>(der, &config).unwrap();
        assert_eq!(rdn_sizes(&name).unwrap(), [1, 1, 1]);
    }
    assert_eq!(enc(&dec::<Name>(der, &Config::DER).unwrap()).unwrap(), der);

    let unsorted = leak(hex(NAME_UNSORTED));
    let name = dec::<Name>(unsorted, &Config::BER).unwrap();
    assert_eq!(rdn_sizes(&name).unwrap(), [1, 2]);
    let name = dec::<Name>(unsorted, &Config::DER).unwrap();
    assert_eq!(kind(rdn_sizes(&name)), (ErrorKind::SetOfNotSorted, 38));

    let sorted = leak(hex(NAME_SORTED));
    let name = dec::<Name>(sorted, &Config::DER).unwrap();
    assert_eq!(rdn_sizes(&name).unwrap(), [1, 2]);
    assert_eq!(enc(&name).unwrap(), sorted);
}

// --- SEQUENCE with every field attribute --------------------------------------------------

#[derive(Asn1, Debug)]
struct Tbs<'a> {
    #[asn1(explicit = 0, default = 0u8, tolerate(encoded_default))]
    version: u8,
    serial: Int<'a>,
    #[asn1(default = false)]
    critical: bool,
    #[asn1(implicit = 1)]
    unique_id: Option<BitString<'a>>,
    #[asn1(explicit = 2)]
    note: Option<Utf8String<'a>>,
    #[asn1(explicit = 3)]
    extensions: Option<SequenceOf<'a, Any<'a>>>,
}

#[test]
fn sequence_with_default_explicit_implicit_and_optional() {
    let minimal = leak(hex("30 05 02 03 01 00 01"));
    let t = dec::<Tbs>(minimal, &Config::DER).unwrap();
    assert_eq!((t.version, t.critical, t.unique_id.is_none()), (0, false, true));
    assert_eq!(t.serial.as_bytes(), &[1, 0, 1]);
    assert_eq!(enc(&t).unwrap(), minimal);

    let bytes = leak(hex(
        "30 1A A0 03 02 01 02 02 02 00 80 01 01 FF 81 02 04 A0 A2 04 0C 02 68 69 A3 02 30 00",
    ));
    let t = dec::<Tbs>(bytes, &Config::DER).unwrap();
    assert_eq!(t.version, 2);
    assert!(t.critical);
    assert_eq!(t.unique_id.as_ref().unwrap().unused_bits(), 4);
    assert_eq!(t.note.as_ref().unwrap().as_str(), "hi");
    assert!(t.extensions.as_ref().unwrap().is_empty());
    assert_eq!(enc(&t).unwrap(), bytes);
    assert!(t.version != 0);
}

#[test]
fn der_rejects_encoded_defaults_unless_the_field_and_config_tolerate() {
    // version [0] 0 and critical FALSE are both DEFAULTs.
    let version = leak(hex("30 0A A0 03 02 01 00 02 03 01 00 01"));
    assert_eq!(kind(dec::<Tbs>(version, &Config::DER)), (ErrorKind::DefaultValueEncoded, 2));
    assert!(dec::<Tbs>(version, &Config::BER).is_ok());
    let tolerant = Config::DER.with_tolerances(Tolerances::NONE.with(Tolerance::EncodedDefault));
    let mut r = SliceReader::new(version, &tolerant);
    assert_eq!(r.read::<Tbs>().unwrap().version, 0);
    assert!(r.deviations().contains(Tolerance::EncodedDefault));
    // `critical` has no tolerate attribute, so the config is not enough.
    let critical = leak(hex("30 08 02 03 01 00 01 01 01 00"));
    assert_eq!(kind(dec::<Tbs>(critical, &tolerant)).0, ErrorKind::DefaultValueEncoded);
    assert!(dec::<Tbs>(critical, &Config::BER).is_ok());
}

#[test]
fn sequence_errors() {
    // Non-extensible: trailing components are rejected.
    let trailing = leak(hex("30 07 02 03 01 00 01 05 00"));
    assert_eq!(kind(dec::<Tbs>(trailing, &Config::DER)), (ErrorKind::TrailingData, 7));
    // A mandatory field is missing.
    assert_eq!(kind(dec::<Tbs>(h("30 00"), &Config::DER)).0, ErrorKind::Truncated);
    // Wrong tag for a mandatory field.
    let wrong = kind(dec::<Tbs>(h("30 02 05 00"), &Config::DER));
    assert_eq!(
        wrong.0,
        ErrorKind::UnexpectedTag { expected: Some(Tag::INTEGER), found: Tag::NULL }
    );
    // Implicit [1] must be a BIT STRING encoding.
    assert!(dec::<Tbs>(h("30 08 02 03 01 00 01 81 01 08"), &Config::DER).is_err());
}

// --- SET ----------------------------------------------------------------------------------

#[derive(Asn1, Debug, PartialEq)]
#[asn1(set)]
struct Settings {
    #[asn1(implicit = 1)]
    beta: u8,
    alpha: bool,
    #[asn1(explicit = 0)]
    gamma: Option<u8>,
}

#[test]
fn set_encodes_by_tag_order_and_decodes_in_any_order_under_ber() {
    let value = Settings { beta: 7, alpha: true, gamma: Some(9) };
    // BOOLEAN [UNIVERSAL 1] < [0] < [1]
    let der = hex("31 0B 01 01 FF A0 03 02 01 09 81 01 07");
    assert_eq!(enc(&value).unwrap(), der);
    assert_eq!(dec::<Settings>(leak(der.clone()), &Config::DER).unwrap(), value);
    let reordered = leak(hex("31 0B 81 01 07 01 01 FF A0 03 02 01 09"));
    assert_eq!(dec::<Settings>(reordered, &Config::BER).unwrap(), value);
    assert_eq!(kind(dec::<Settings>(reordered, &Config::DER)), (ErrorKind::SetOfNotSorted, 5));
    let without = Settings { beta: 7, alpha: false, gamma: None };
    assert_eq!(enc(&without).unwrap(), hex("31 06 01 01 00 81 01 07"));
    // Duplicates, unknown members and missing members.
    assert_eq!(
        kind(dec::<Settings>(h("31 06 81 01 07 81 01 07"), &Config::BER)).0,
        ErrorKind::UnexpectedTag { expected: None, found: Tag::context(1) }
    );
    assert_eq!(
        kind(dec::<Settings>(h("31 03 05 00 00"), &Config::BER)).0,
        ErrorKind::UnexpectedTag { expected: None, found: Tag::NULL }
    );
    assert_eq!(kind(dec::<Settings>(h("31 03 01 01 FF"), &Config::BER)).0, ErrorKind::Truncated);
}

// --- CHOICE -------------------------------------------------------------------------------

#[derive(Asn1, Debug, PartialEq)]
enum Choice<'a> {
    Number(u8),
    Text(Utf8String<'a>),
    #[asn1(explicit = 0)]
    Wrapped(OctetString<'a>),
    #[asn1(implicit = 1)]
    Nothing(Null),
}

#[derive(Asn1, Debug, PartialEq)]
struct Holder<'a> {
    #[asn1(default = false)]
    flag: bool,
    choice: Choice<'a>,
    #[asn1(explicit = 5)]
    tagged_choice: Option<Choice<'a>>,
}

#[test]
fn choice_dispatches_on_tag_and_nests() {
    for (bytes, expected) in [
        ("02 01 05", Choice::Number(5)),
        ("0C 02 68 69", Choice::Text(Utf8String::new("hi"))),
        ("A0 03 04 01 AA", Choice::Wrapped(OctetString::new(&[0xAA]))),
        ("81 00", Choice::Nothing(Null)),
    ] {
        let bytes = leak(hex(bytes));
        let got = dec::<Choice>(bytes, &Config::DER).unwrap();
        assert_eq!(got, expected);
        assert_eq!(enc(&got).unwrap(), bytes);
        assert!(Choice::matches_tag(Tag::context(0)));
    }
    assert_eq!(
        kind(dec::<Choice>(h("05 00"), &Config::DER)).0,
        ErrorKind::UnexpectedTag { expected: None, found: Tag::NULL }
    );
    assert_eq!(kind(dec::<Choice>(h(""), &Config::DER)).0, ErrorKind::Truncated);
    // A tagged CHOICE is explicit.
    let bytes = leak(hex("30 08 02 01 05 A5 03 0C 01 41"));
    let holder = dec::<Holder>(bytes, &Config::DER).unwrap();
    assert_eq!(
        holder,
        Holder {
            flag: false,
            choice: Choice::Number(5),
            tagged_choice: Some(Choice::Text(Utf8String::new("A")))
        }
    );
    assert_eq!(enc(&holder).unwrap(), bytes);
    assert_eq!(<Choice as StaticTags>::TAGS.len(), 4);
}

#[derive(Asn1, Debug, PartialEq)]
#[asn1(extensible)]
enum Open<'a> {
    Number(u8),
    Unknown(Any<'a>),
}

#[test]
fn extensible_choice_captures_unknown_alternatives() {
    let n = dec::<Open>(h("02 01 05"), &Config::DER).unwrap();
    assert_eq!(n, Open::Number(5));
    let Open::Unknown(any) = dec::<Open>(h("83 02 AA BB"), &Config::DER).unwrap() else { panic!() };
    assert_eq!((any.tag(), any.contents()), (Tag::context(3), &[0xAA, 0xBB][..]));
    assert_eq!(enc(&Open::Unknown(any)).unwrap(), hex("83 02 AA BB"));
}

// --- Extensibility ------------------------------------------------------------------------

#[derive(Asn1, Debug)]
#[asn1(extensible)]
struct Skipping {
    version: u8,
}

#[derive(Asn1, Debug)]
struct Capturing<'a> {
    version: u8,
    rest: Unknown<'a>,
}

#[test]
fn extensible_structs_skip_or_capture_trailing_components() {
    let bytes = leak(hex("30 0A 02 01 01 05 00 04 01 AA 80 00"));
    assert_eq!(dec::<Skipping>(bytes, &Config::DER).unwrap().version, 1);
    let c = dec::<Capturing>(bytes, &Config::DER).unwrap();
    let tags: Vec<_> = c.rest.iter().map(|a| a.unwrap().tag()).collect();
    assert_eq!(tags, [Tag::NULL, Tag::OCTET_STRING, Tag::context(0)]);
    assert_eq!(enc(&c).unwrap(), bytes);
    // Unknown components must still be well-formed.
    assert!(dec::<Skipping>(h("30 05 02 01 01 04 05"), &Config::DER).is_err());
    assert_eq!(dec::<Capturing>(h("30 03 02 01 01"), &Config::DER).unwrap().rest.is_empty(), true);
}

// --- Constraints --------------------------------------------------------------------------

const UB_NAME: u32 = 5;

fn is_even(v: &u32) -> bool {
    v % 2 == 0
}

#[derive(Asn1, Debug, PartialEq)]
#[asn1(transparent, constraint = "SIZE (6 | 8 | 12 | 16)")]
struct MacAddress<'a>(pub OctetString<'a>);

#[derive(Asn1, Debug, PartialEq)]
struct Constrained<'a> {
    #[asn1(constraint = "1..UB_NAME")]
    named_bound: u32,
    #[asn1(constraint = "0<..<100")]
    exclusive: u32,
    #[asn1(constraint = "(0..10 | 20..30) EXCEPT 25")]
    except: u32,
    #[asn1(constraint = "ALL EXCEPT (3 | 4)")]
    all_except: u8,
    #[asn1(constraint = "0..100", constraint = "50..MAX")]
    serial: u32,
    #[asn1(constraint = "SIZE (1..8, ...)")]
    extensible: OctetString<'a>,
    #[asn1(constraint = r#"FROM ("a".."z" | "0".."9")"#)]
    alphabet: Utf8String<'a>,
    #[asn1(validate = is_even)]
    even: Option<u32>,
}

#[test]
fn mac_address_vectors() {
    for hex_text in [
        "04 06 00 24 98 7B 19 02",
        "04 08 AC DE 48 00 11 22 33 44",
        "04 0C 00 00 00 00 00 00 03 00 00 00 00 00",
    ] {
        let bytes = leak(hex(hex_text));
        let mac = dec::<MacAddress>(bytes, &Config::DER).unwrap();
        assert_eq!(enc(&mac).unwrap(), bytes);
    }
    let seven = leak(hex("04 07 00 24 98 7B 19 02 00"));
    assert_eq!(kind(dec::<MacAddress>(seven, &Config::DER)), (ErrorKind::ConstraintViolated, 0));
    let bad = MacAddress(OctetString::new(&seven[2..]));
    let e = enc(&bad).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::ConstraintViolated);
}

fn constrained(parts: [&str; 7]) -> Vec<u8> {
    let body = hex(&parts.join(" "));
    [vec![0x30, body.len() as u8], body].concat()
}

#[test]
fn constraint_notation() {
    let ok =
        ["02 01 03", "02 01 50", "02 01 05", "02 01 05", "02 01 50", "04 02 AA BB", "0C 02 61 39"];
    let base = constrained(ok);
    // `serial` is 0..100 and 50..MAX: only 50..=100 passes.
    let value = dec::<Constrained>(leak(base.clone()), &Config::DER);
    assert!(value.is_ok(), "{value:?}");
    assert_eq!(enc(&value.unwrap()).unwrap(), base);

    let bad = |index: usize, replacement: &str| {
        let mut parts = ok;
        parts[index] = replacement;
        dec::<Constrained>(leak(constrained(parts)), &Config::DER)
    };
    // named bound 1..=5
    assert!(bad(0, "02 01 00").is_err());
    assert!(bad(0, "02 01 06").is_err());
    assert!(bad(0, "02 01 01").is_ok());
    // 0<..<100 excludes both ends.
    assert!(bad(1, "02 01 00").is_err());
    assert!(bad(1, "02 01 64").is_err());
    assert!(bad(1, "02 01 63").is_ok());
    // (0..10 | 20..30) EXCEPT 25
    assert!(bad(2, "02 01 0A").is_ok());
    assert!(bad(2, "02 01 0B").is_err());
    assert!(bad(2, "02 01 19").is_err());
    assert!(bad(2, "02 01 1E").is_ok());
    // ALL EXCEPT (3 | 4)
    assert!(bad(3, "02 01 03").is_err());
    assert!(bad(3, "02 01 04").is_err());
    assert!(bad(3, "02 01 02").is_ok());
    // serial: intersection of 0..100 and 50..MAX
    assert!(bad(4, "02 01 31").is_err());
    assert!(bad(4, "02 01 32").is_ok());
    assert!(bad(4, "02 01 64").is_ok());
    assert!(bad(4, "02 01 65").is_err());
    // extension marker: SIZE (1..8, ...) is parsed but not enforced
    assert!(bad(5, "04 00").is_ok());
    assert!(bad(5, "04 09 00 00 00 00 00 00 00 00 00").is_ok());
    // FROM: characters are checked, not bytes
    assert!(bad(6, "0C 01 41").is_err());
    assert!(bad(6, "0C 03 61 62 2D").is_err());
    assert!(bad(6, "0C 00").is_ok());
}

#[test]
fn validate_hook_on_optional_fields() {
    let with = |even: &str| {
        let ok = [
            "02 01 03", "02 01 50", "02 01 05", "02 01 05", "02 01 64", "04 02 AA BB",
            "0C 02 61 39",
        ];
        let body = hex(&format!("{} {even}", ok.join(" ")));
        leak([vec![0x30, body.len() as u8], body].concat())
    };
    assert_eq!(dec::<Constrained>(with("02 01 04"), &Config::DER).unwrap().even, Some(4));
    assert_eq!(
        kind(dec::<Constrained>(with("02 01 05"), &Config::DER)),
        (ErrorKind::ConstraintViolated, 25)
    );
    let absent = leak(constrained([
        "02 01 03", "02 01 50", "02 01 05", "02 01 05", "02 01 64", "04 02 AA BB", "0C 02 61 39",
    ]));
    assert_eq!(dec::<Constrained>(absent, &Config::DER).unwrap().even, None);
}

// --- DEFINED BY ---------------------------------------------------------------------------

struct KnownParams;
impl DefinedBySet for KnownParams {
    fn decode_defined<'a>(id: &Oid<'_>, value: Any<'a>) -> Result<Option<Self>, Error> {
        if *id == oid!("1.2.3") {
            // Known parameters must be a NULL.
            let r = value.contents_reader(&Config::DER);
            return if value.tag() == Tag::NULL && r.is_empty() {
                Ok(Some(KnownParams))
            } else {
                Err(Error::new(
                    ErrorKind::UnexpectedTag { expected: Some(Tag::NULL), found: value.tag() },
                    0,
                ))
            };
        }
        Ok(None)
    }
}

#[derive(Asn1, Debug)]
struct AlgorithmIdentifier<'a> {
    algorithm: Oid<'a>,
    #[asn1(defined_by = "algorithm", set = KnownParams)]
    parameters: Option<Any<'a>>,
}

#[test]
fn defined_by_decodes_open_types_through_the_set() {
    let known = dec::<AlgorithmIdentifier>(h("30 06 06 02 2A 03 05 00"), &Config::DER).unwrap();
    assert!(known.parameters.is_some());
    assert!(dec::<AlgorithmIdentifier>(h("30 06 06 02 2A 03 04 00"), &Config::DER).is_err());
    let other = dec::<AlgorithmIdentifier>(h("30 06 06 02 2A 04 04 00"), &Config::DER).unwrap();
    assert_eq!(other.parameters.unwrap().tag(), Tag::OCTET_STRING);
}

// --- der / tolerate / validate hooks ------------------------------------------------------

#[derive(Asn1, Debug)]
struct StrictInside<'a> {
    #[asn1(der)]
    attributes: Any<'a>,
}

fn at_least_one(v: &Validated) -> bool {
    v.count >= 1
}

#[derive(Asn1, Debug, PartialEq)]
#[asn1(validate = at_least_one)]
struct Validated {
    count: u8,
}

#[test]
fn der_attribute_tightens_rules_for_one_field() {
    // BER SEQUENCE (indefinite) with a non-minimal length inside the DER field.
    let loose = leak(hex("30 80 31 03 04 81 00 00 00"));
    assert!(dec::<StrictInside>(loose, &Config::BER).is_ok());
    let inside_der = leak(hex("30 80 31 82 00 02 04 00 00 00"));
    assert_eq!(kind(dec::<StrictInside>(inside_der, &Config::BER)).0, ErrorKind::NonMinimalLength);
}

#[test]
fn type_level_validate_hook() {
    assert_eq!(
        dec::<Validated>(h("30 03 02 01 01"), &Config::DER).unwrap(),
        Validated { count: 1 }
    );
    assert_eq!(
        kind(dec::<Validated>(h("30 03 02 01 00"), &Config::DER)),
        (ErrorKind::ConstraintViolated, 0)
    );
    assert_eq!(enc(&Validated { count: 0 }).unwrap_err().kind(), &ErrorKind::ConstraintViolated);
    assert_eq!(enc(&Validated { count: 3 }).unwrap(), hex("30 03 02 01 03"));
}

#[test]
fn oid_macro() {
    const SHA256_RSA: Oid<'static> = oid!("1.2.840.113549.1.1.11");
    assert_eq!(SHA256_RSA.as_bytes(), &hex("2A 86 48 86 F7 0D 01 01 0B")[..]);
    assert_eq!(oid!("2.5.4.3"), Oid::new(&[0x55, 0x04, 0x03]).unwrap());
    assert_eq!(oid!("2.999.3").arcs().collect::<Vec<_>>(), [2, 999, 3]);
}
