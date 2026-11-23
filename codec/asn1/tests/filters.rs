mod common;

use bouncycastle_asn1::*;
use common::{Ev, hex, run};

type Pipeline = StringReassembler<ContentValidator<Tokenizer<32>>>;

fn pipeline(config: Config) -> Pipeline {
    StringReassembler::new(ContentValidator::new(Tokenizer::<32>::new(config)))
}

fn content_of(events: &[Ev]) -> Vec<u8> {
    events
        .iter()
        .filter_map(|e| if let Ev::Content(c) = e { Some(c.clone()) } else { None })
        .flatten()
        .collect()
}

fn outcome(data: &str, config: Config, chunk: usize) -> Result<Vec<Ev>, (ErrorKind, u64)> {
    run(&mut pipeline(config), &hex(data), chunk).map_err(|e| (e.kind().clone(), e.offset()))
}

fn invalid(data: &str, config: Config, error: ValueError, offset: u64) {
    for chunk in [usize::MAX, 1, 2, 3] {
        assert_eq!(
            outcome(data, config.clone(), chunk),
            Err((ErrorKind::InvalidValue(error.clone()), offset)),
            "{data} chunk {chunk}"
        );
    }
}

fn valid(data: &str, config: Config) -> Vec<Ev> {
    let first = outcome(data, config.clone(), usize::MAX).unwrap();
    for chunk in [1, 2, 3, 5] {
        assert_eq!(outcome(data, config.clone(), chunk).unwrap(), first, "{data} chunk {chunk}");
    }
    first
}

#[test]
fn constructed_octet_strings_reassemble_to_the_der_contents() {
    let der = valid("04 08 01 23 45 67 89 AB CD EF", Config::DER);
    let primitive_content = content_of(&der);
    for data in [
        "24 0C 04 04 01 23 45 67 04 04 89 AB CD EF",
        "24 80 04 04 01 23 45 67 04 04 89 AB CD EF 00 00",
        "24 80 04 04 01 23 45 67 24 80 04 02 89 AB 04 02 CD EF 00 00 00 00",
        "24 80 04 04 01 23 45 67 24 06 04 04 89 AB CD EF 00 00",
    ] {
        let events = valid(data, Config::BER);
        assert_eq!(content_of(&events), primitive_content, "{data}");
        assert!(
            matches!(&events[0], Ev::Header { tag, constructed: false, depth: 0, .. } if *tag == Tag::OCTET_STRING)
        );
        assert!(matches!(events.last(), Some(Ev::End { depth: 0, start: 0, .. })));
        assert_eq!(events.len(), 3, "one Header, merged Content and one End: {events:?}");
    }
    // Constructed strings are not allowed under DER.
    assert_eq!(
        outcome("24 0C 04 04 01 23 45 67 04 04 89 AB CD EF", Config::DER, 4),
        Err((ErrorKind::ConstructedNotAllowed, 0))
    );
}

#[test]
fn all_zero_constructed_indefinite_octet_string() {
    let events = valid(
        "24 80 04 04 00 00 00 00 04 04 00 00 00 00 00 00",
        Config::BER.with_value_count(ValueCount::Many),
    );
    assert_eq!(content_of(&events), vec![0; 8]);
}

#[test]
fn bit_strings_strip_unused_bits_octets() {
    let mut primitive = pipeline(Config::DER);
    let events = run(&mut primitive, &hex("03 04 06 6E 5D C0"), 2).unwrap();
    assert_eq!(content_of(&events), [0x6E, 0x5D, 0xC0]);
    assert_eq!(primitive.last_unused_bits(), Some(6));
    for data in ["23 09 03 03 00 6E 5D 03 02 06 C0", "23 80 03 03 00 6E 5D 03 02 06 C0 00 00"] {
        for chunk in [usize::MAX, 1, 2, 4] {
            let mut ber = pipeline(Config::BER);
            let events = run(&mut ber, &hex(data), chunk).unwrap();
            assert_eq!(content_of(&events), [0x6E, 0x5D, 0xC0], "{data} chunk {chunk}");
            assert_eq!(ber.last_unused_bits(), Some(6));
        }
    }
    // Only the last segment may have unused bits.
    invalid("23 09 03 03 06 6E 5D 03 02 00 C0", Config::BER, ValueError::BitStringUnusedBits, 7);
    invalid("03 00", Config::BER, ValueError::BitStringUnusedBits, 0);
    invalid("03 01 01", Config::BER, ValueError::BitStringUnusedBits, 0);
    invalid("03 02 08 00", Config::BER, ValueError::BitStringUnusedBits, 2);
    // Padding bits: BER any, DER zero.
    valid("03 04 06 6E 5D E0", Config::BER);
    invalid("03 04 06 6E 5D E0", Config::DER, ValueError::BitStringPaddingNotZero, 0);
    // The value is available even for the empty bit string.
    let mut empty = pipeline(Config::DER);
    run(&mut empty, &hex("03 01 00"), 1).unwrap();
    assert_eq!(empty.last_unused_bits(), Some(0));
}

#[test]
fn segments_must_carry_the_segment_tag() {
    fn wrong_tag(data: &str, expected: Tag, found: Tag, offset: u64) {
        for chunk in [usize::MAX, 1, 2] {
            assert_eq!(
                outcome(data, Config::BER, chunk),
                Err((ErrorKind::UnexpectedTag { expected: Some(expected), found }, offset)),
                "{data} chunk {chunk}"
            );
        }
    }
    wrong_tag("24 80 04 01 AA 03 02 00 FF 00 00", Tag::OCTET_STRING, Tag::BIT_STRING, 5);
    wrong_tag("23 80 04 01 00 00 00", Tag::BIT_STRING, Tag::OCTET_STRING, 2);
    wrong_tag("2C 80 0C 01 41 00 00", Tag::OCTET_STRING, Tag::UTF8_STRING, 2);
    wrong_tag("36 06 16 01 41 16 01 42", Tag::OCTET_STRING, Tag::IA5_STRING, 2);
    wrong_tag("33 80 04 01 41 13 01 42 00 00", Tag::OCTET_STRING, Tag::PRINTABLE_STRING, 5);
    wrong_tag("2C 80 03 02 00 41 00 00", Tag::OCTET_STRING, Tag::BIT_STRING, 2);
    wrong_tag("2C 80 24 80 0C 01 41 00 00 00 00", Tag::OCTET_STRING, Tag::UTF8_STRING, 4);
}

/// Examples from draft-housley-asn1-layman-guide.
#[test]
fn layman_guide_constructed_examples_reassemble() {
    for (der, ber) in [
        // 5.7 IA5String "test1@example.com", definite and indefinite.
        (
            "16 11 74 65 73 74 31 40 65 78 61 6D 70 6C 65 2E 63 6F 6D",
            "36 17 04 05 74 65 73 74 31 04 01 40 04 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D",
        ),
        (
            "16 11 74 65 73 74 31 40 65 78 61 6D 70 6C 65 2E 63 6F 6D",
            "36 80 04 05 74 65 73 74 31 04 01 40 04 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D 00 00",
        ),
        // 5.11 OCTET STRING.
        ("04 08 01 23 45 67 89 AB CD EF", "24 0C 04 04 01 23 45 67 04 04 89 AB CD EF"),
        // 5.12 PrintableString "Test User 1", definite and indefinite.
        (
            "13 0B 54 65 73 74 20 55 73 65 72 20 31",
            "33 0F 04 05 54 65 73 74 20 04 06 55 73 65 72 20 31",
        ),
        (
            "13 0B 54 65 73 74 20 55 73 65 72 20 31",
            "33 80 04 05 54 65 73 74 20 04 06 55 73 65 72 20 31 00 00",
        ),
        // 5.18 T61String "clés publiques".
        (
            "14 0F 63 6C C2 65 73 20 70 75 62 6C 69 71 75 65 73",
            "34 15 04 05 63 6C C2 65 73 04 01 20 04 09 70 75 62 6C 69 71 75 65 73",
        ),
        // 5.21 UTF8String U+D55C U+AD6D U+C5B4, definite and indefinite.
        ("0C 09 ED 95 9C EA B5 AD EC 96 B4", "2C 0D 04 03 ED 95 9C 04 06 EA B5 AD EC 96 B4"),
        (
            "0C 09 ED 95 9C EA B5 AD EC 96 B4",
            "2C 80 04 03 ED 95 9C 04 06 EA B5 AD EC 96 B4 00 00",
        ),
        // Nested segment.
        ("0C 02 41 42", "2C 80 24 80 04 01 41 00 00 04 01 42 00 00"),
    ] {
        let primitive = valid(der, Config::DER);
        let events = valid(ber, Config::BER);
        assert_eq!(content_of(&events), content_of(&primitive), "{ber}");
        let Ev::Header { tag: der_tag, .. } = &primitive[0] else { panic!("{der}") };
        assert!(
            matches!(&events[0], Ev::Header { tag, constructed: false, depth: 0, .. } if tag == der_tag),
            "{ber}"
        );
        assert_eq!(events.len(), 3, "{ber}: {events:?}");
    }
}

#[test]
fn small_primitives_are_validated_whole() {
    invalid("02 02 00 7F", Config::BER, ValueError::IntegerNotMinimal, 2);
    invalid("02 00", Config::DER, ValueError::IntegerEmpty, 2);
    invalid("0A 02 FF 80", Config::DER, ValueError::IntegerNotMinimal, 2);
    invalid("05 01 00", Config::BER, ValueError::NullNotEmpty, 2);
    invalid("06 00", Config::BER, ValueError::OidEmpty, 2);
    invalid("06 03 2A 80 01", Config::BER, ValueError::OidNotMinimal, 2);
    invalid("0D 02 2A 86", Config::BER, ValueError::OidTruncated, 2);
    invalid("01 02 FF FF", Config::BER, ValueError::BooleanLength, 2);
    invalid("01 00", Config::BER, ValueError::BooleanLength, 2);
    invalid("01 01 02", Config::DER, ValueError::BooleanNotDer, 2);
    valid("01 01 02", Config::BER);
    valid("02 02 00 80", Config::DER);
    valid("06 06 2A 86 48 86 F7 0D", Config::DER);
    valid("0D 05 81 FD 59 03 02", Config::DER);
    // Inside constructed values, at the right offsets.
    invalid("30 05 02 03 00 00 01", Config::BER, ValueError::IntegerNotMinimal, 4);
    // Unknown and non-universal tags pass through unvalidated.
    valid("80 02 00 7F", Config::DER);
    valid("A0 03 80 01 00", Config::DER);
}

#[test]
fn strings_are_validated_incrementally() {
    valid("0C 09 ED 95 9C EA B5 AD EC 96 B4", Config::DER);
    invalid("0C 02 C3 28", Config::DER, ValueError::InvalidCharacterEncoding, 3);
    invalid("0C 01 C3", Config::DER, ValueError::InvalidCharacterEncoding, 0);
    invalid("0C 03 ED A0 80", Config::DER, ValueError::InvalidCharacterEncoding, 4);
    invalid("0C 01 FF", Config::DER, ValueError::InvalidCharacterEncoding, 2);
    invalid("13 02 41 40", Config::DER, ValueError::NotInAlphabet, 3);
    invalid("16 01 80", Config::DER, ValueError::NotInAlphabet, 2);
    invalid("1A 01 7F", Config::DER, ValueError::NotInAlphabet, 2);
    invalid("12 01 41", Config::DER, ValueError::NotInAlphabet, 2);
    valid("13 0B 54 65 73 74 20 55 73 65 72 20 31", Config::DER);
    valid("16 11 74 65 73 74 31 40 65 78 61 6D 70 6C 65 2E 63 6F 6D", Config::DER);
    valid("1E 04 00 41 20 AC", Config::DER);
    invalid("1E 03 00 41 20", Config::DER, ValueError::InvalidLength, 0);
    invalid("1E 02 D8 00", Config::DER, ValueError::InvalidCharacterEncoding, 3);
    valid("1C 08 00 00 00 41 00 01 F6 00", Config::DER);
    invalid("1C 06 00 00 00 41 00 00", Config::DER, ValueError::InvalidLength, 0);
    invalid("1C 04 00 11 00 00", Config::DER, ValueError::InvalidCharacterEncoding, 5);
    // A character may straddle segments of a constructed string.
    let events = valid("2C 80 04 02 ED 95 04 01 9C 00 00", Config::BER);
    assert_eq!(content_of(&events), [0xED, 0x95, 0x9C]);
    invalid(
        "2C 80 04 02 ED 95 04 01 28 00 00",
        Config::BER,
        ValueError::InvalidCharacterEncoding,
        8,
    );
    // Teletex and octet strings are opaque.
    valid("14 02 FF 00", Config::DER);
}

#[test]
fn times_are_copied_across_segments_and_decoded_at_the_end() {
    valid("17 0D 39 31 30 35 30 36 32 33 34 35 34 30 5A", Config::DER);
    let constructed = "37 80 04 04 39 31 30 35 04 09 30 36 32 33 34 35 34 30 5A 00 00";
    valid(constructed, Config::BER);
    invalid(
        "17 0D 39 37 30 32 32 39 30 30 30 30 30 30 5A",
        Config::DER,
        ValueError::InvalidTime,
        0,
    );
    invalid(
        "18 0F 31 39 30 30 30 32 32 39 30 30 30 30 30 30 5A",
        Config::BER,
        ValueError::InvalidTime,
        0,
    );
    // Longer than the longest valid time is rejected as soon as it exceeds it.
    let long = "37 80 04 08 30 30 30 30 30 30 30 30 04 08 30 30 30 30 30 30 30 30 04 08 30 30 30 30 30 30 30 30 00 00";
    invalid(long, Config::BER, ValueError::InvalidLength, 25);
    // The stack copies the segments of a nested definite-length constructed time.
    valid("37 13 04 04 39 31 30 35 24 0B 04 09 30 36 32 33 34 35 34 30 5A", Config::BER);
    assert_eq!(
        outcome("37 80 17 01 39 00 00", Config::BER, 3),
        Err((
            ErrorKind::UnexpectedTag { expected: Some(Tag::OCTET_STRING), found: Tag::UTC_TIME },
            2
        ))
    );
    // Works without the reassembler.
    let mut bare = ContentValidator::new(Tokenizer::<32>::new(Config::BER));
    assert!(run(&mut bare, &hex(constructed), 2).is_ok());
}

#[test]
fn caller_can_skip_or_tighten_after_a_header() {
    let data = hex("30 80 02 02 00 7F 00 00");
    let mut source = ContentValidator::new(Tokenizer::<32>::new(Config::BER));
    let mut input = &data[..];
    let s = source.step(input, true).unwrap();
    input = &input[s.consumed..];
    // Skipping the SEQUENCE skips the validation of its contents.
    source.skip_content().unwrap();
    let mut ended = false;
    while !ended {
        let s = source.step(input, true).unwrap();
        input = &input[s.consumed..];
        ended = matches!(s.kind, StepKind::Event(Event::End { .. }));
    }

    // Tightening to DER makes the validator apply DER rules.
    let data = hex("30 80 01 01 02 00 00");
    let mut source = ContentValidator::new(Tokenizer::<32>::new(Config::BER));
    let mut input = &data[..];
    let s = source.step(input, true).unwrap();
    input = &input[s.consumed..];
    source.tighten_rules(Rules::Der).unwrap();
    assert_eq!(source.rules(), Rules::Der);
    let s = source.step(input, true).unwrap();
    input = &input[s.consumed..];
    let e = loop {
        match source.step(input, true) {
            Ok(s) => input = &input[s.consumed..],
            Err(e) => break e,
        }
    };
    assert_eq!(e.kind(), &ErrorKind::InvalidValue(ValueError::BooleanNotDer));
    // gather_content is also allowed by the caller.
    let mut source = ContentValidator::new(Tokenizer::<32>::new(Config::DER));
    let data = hex("02 01 05");
    let s = source.step(&data, true).unwrap();
    assert_eq!(s.consumed, 2);
    source.gather_content().unwrap();
    assert_eq!(source.position(), 2);
    assert_eq!(source.depth(), 1);
    assert!(source.deviations().is_empty());
    let inner = source.into_inner();
    assert_eq!(inner.position(), 2);
    let _ = pipeline(Config::DER).into_inner().into_inner();
}
