mod common;

use bouncycastle_asn1::*;
use common::{hex, run};
use proptest::prelude::*;

fn id(tag: Tag, constructed: bool) -> Identifier {
    Identifier { tag, constructed }
}

#[test]
fn encode_to_slice_checks_size_first_and_writes_nothing() {
    let value = OctetString::new(&[1, 2, 3, 4]);
    assert_eq!(value.encoded_len().unwrap(), 6);
    for size in 0..6 {
        let mut buf = vec![0xEE; size];
        let e = encode_to_slice(&value, &mut buf).unwrap_err();
        assert_eq!(e.kind(), &ErrorKind::InsufficientSize { required: 6 });
        assert!(buf.iter().all(|&b| b == 0xEE), "nothing written");
    }
    let mut buf = [0u8; 10];
    assert_eq!(encode_to_slice(&value, &mut buf).unwrap(), &hex("04 04 01 02 03 04")[..]);
    assert_eq!(&buf[6..], &[0; 4]);
}

#[test]
fn writer_reports_the_total_size_needed() {
    let mut buf = [0u8; 4];
    let mut w = Writer::new(&mut buf);
    w.write_header(id(Tag::OCTET_STRING, false), 2).unwrap();
    assert_eq!(w.position(), 2);
    let e = w.write_bytes(&[1, 2, 3]).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::InsufficientSize { required: 5 });
    assert_eq!(w.position(), 2);
    w.write_bytes(&[1, 2]).unwrap();
    assert_eq!(buf, [0x04, 0x02, 1, 2]);
}

#[test]
fn large_lengths_use_long_form() {
    let data = vec![7u8; 300];
    let value = OctetString::new(&data);
    let mut buf = vec![0u8; 304];
    let out = encode_to_slice(&value, &mut buf).unwrap();
    assert_eq!(&out[..4], &[0x04, 0x82, 0x01, 0x2C]);
    let back = SliceReader::new(out, &Config::DER).read::<OctetString>().unwrap();
    assert_eq!(back.as_bytes(), &data[..]);
    assert_eq!(header_len(Tag::OCTET_STRING, false, 300), 4);
}

#[test]
fn sequences_and_collections_encode() {
    let ints = [1u8, 2, 3];
    let seq = SequenceOfRef(&ints);
    let mut buf = [0u8; 16];
    assert_eq!(
        encode_to_slice(&seq, &mut buf).unwrap(),
        &hex("30 09 02 01 01 02 01 02 02 01 03")[..]
    );
    let empty: [u8; 0] = [];
    assert_eq!(encode_to_slice(&SequenceOfRef(&empty), &mut buf).unwrap(), &[0x30, 0x00]);
    assert_eq!(
        encode_to_slice(&SetOfRef(&ints), &mut buf).unwrap(),
        &hex("31 09 02 01 01 02 01 02 02 01 03")[..]
    );
    // Option encodes nothing when absent.
    assert_eq!(None::<u8>.encoded_len().unwrap(), 0);
    assert_eq!(Some(5u8).encoded_len().unwrap(), 3);
}

#[cfg(feature = "alloc")]
#[test]
fn vec_is_a_sequence_of() {
    let v = vec![1u8, 2];
    let mut buf = [0u8; 8];
    let out = encode_to_slice(&v, &mut buf).unwrap();
    assert_eq!(out, &hex("30 06 02 01 01 02 01 02")[..]);
    let back = SliceReader::new(out, &Config::DER).read::<Vec<u8>>().unwrap();
    assert_eq!(back, v);
}

#[cfg(feature = "heapless")]
#[test]
fn heapless_vec_is_bounded() {
    let bytes = hex("30 09 02 01 01 02 01 02 02 01 03");
    let ok = SliceReader::new(&bytes, &Config::DER).read::<heapless::Vec<u8, 3>>().unwrap();
    assert_eq!(ok.as_slice(), &[1, 2, 3]);
    let e = SliceReader::new(&bytes, &Config::DER).read::<heapless::Vec<u8, 2>>().unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::CapacityExceeded, 8));
    let mut buf = [0u8; 16];
    assert_eq!(encode_to_slice(&ok, &mut buf).unwrap(), &bytes[..]);
}

fn stream(rules: Rules, steps: &[Step]) -> Result<Vec<u8>, Error> {
    let mut encoder = StreamEncoder::<4>::new(rules);
    let mut out = Vec::new();
    for step in steps {
        let mut buf = [0u8; 32];
        let n = match step {
            Step::Begin(i, l) => encoder.begin(*i, *l, &mut buf)?,
            Step::Content(c) => encoder.content(c, &mut buf)?,
            Step::End => encoder.end(&mut buf)?,
        };
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

enum Step {
    Begin(Identifier, Length),
    Content(&'static [u8]),
    End,
}

#[test]
fn stream_encoder_definite_and_indefinite() {
    use Step::*;
    let octets = id(Tag::OCTET_STRING, false);
    let seq = id(Tag::SEQUENCE, true);
    let out = stream(
        Rules::Der,
        &[Begin(octets, Length::Definite(4)), Content(&[1, 2]), Content(&[3, 4]), End],
    )
    .unwrap();
    assert_eq!(out, hex("04 04 01 02 03 04"));
    let out = stream(
        Rules::Der,
        &[
            Begin(seq, Length::Definite(8)),
            Begin(octets, Length::Definite(1)),
            Content(&[9]),
            End,
            Begin(octets, Length::Definite(3)),
            Content(&[1, 2, 3]),
            End,
            End,
        ],
    )
    .unwrap();
    assert_eq!(out, hex("30 08 04 01 09 04 03 01 02 03"));
    let constructed_octets = id(Tag::OCTET_STRING, true);
    let out = stream(
        Rules::Ber,
        &[
            Begin(constructed_octets, Length::Indefinite),
            Begin(octets, Length::Definite(2)),
            Content(&[1, 2]),
            End,
            Begin(octets, Length::Definite(1)),
            Content(&[3]),
            End,
            End,
        ],
    )
    .unwrap();
    assert_eq!(out, hex("24 80 04 02 01 02 04 01 03 00 00"));
    // The output is what the tokenizer reads back.
    let events = run(&mut Tokenizer::<8>::new(Config::BER), &out, 3).unwrap();
    assert_eq!(events.len(), 1 + 2 * 3 + 1 + 1 - 1 + 1 - 1);
    // An indefinite SEQUENCE inside a definite one counts its header and end-of-contents.
    let out = stream(
        Rules::Ber,
        &[
            Begin(seq, Length::Definite(6)),
            Begin(seq, Length::Indefinite),
            Begin(octets, Length::Definite(0)),
            End,
            End,
            End,
        ],
    )
    .unwrap();
    assert_eq!(out, hex("30 06 30 80 04 00 00 00"));
}

#[test]
fn stream_encoder_enforces_lengths_and_state() {
    use Step::*;
    let octets = id(Tag::OCTET_STRING, false);
    let seq = id(Tag::SEQUENCE, true);
    let kind = |steps: &[Step], rules| stream(rules, steps).unwrap_err().kind().clone();
    assert_eq!(
        kind(&[Begin(seq, Length::Indefinite)], Rules::Der),
        ErrorKind::IndefiniteNotAllowed
    );
    assert_eq!(
        kind(&[Begin(octets, Length::Indefinite)], Rules::Ber),
        ErrorKind::IndefiniteOnPrimitive
    );
    assert_eq!(
        kind(&[Begin(octets, Length::Definite(1)), Content(&[1, 2])], Rules::Der),
        ErrorKind::ChildOverrunsParent
    );
    assert_eq!(
        kind(&[Begin(octets, Length::Definite(2)), Content(&[1]), End], Rules::Der),
        ErrorKind::Truncated
    );
    assert_eq!(kind(&[End], Rules::Der), ErrorKind::InvalidState);
    assert_eq!(kind(&[Content(&[1])], Rules::Der), ErrorKind::InvalidState);
    assert_eq!(
        kind(&[Begin(seq, Length::Definite(0)), Content(&[1])], Rules::Der),
        ErrorKind::InvalidState
    );
    assert_eq!(
        kind(&[Begin(octets, Length::Definite(1)), Begin(octets, Length::Definite(0))], Rules::Der),
        ErrorKind::InvalidState
    );
    // A child must fit its definite-length parent.
    assert_eq!(
        kind(&[Begin(seq, Length::Definite(2)), Begin(octets, Length::Definite(1))], Rules::Der),
        ErrorKind::ChildOverrunsParent
    );
    assert_eq!(
        kind(
            &[
                Begin(seq, Length::Definite(4)),
                Begin(seq, Length::Indefinite),
                Begin(octets, Length::Definite(1))
            ],
            Rules::Ber
        ),
        ErrorKind::ChildOverrunsParent
    );
    // Depth.
    let deep: Vec<Step> = (0..5).map(|i| Begin(seq, Length::Definite(1000 - 100 * i))).collect();
    assert_eq!(kind(&deep, Rules::Der), ErrorKind::DepthExceeded);
}

#[test]
fn stream_encoder_insufficient_size_changes_nothing() {
    let mut encoder = StreamEncoder::<4>::new(Rules::Ber);
    let octets = id(Tag::OCTET_STRING, false);
    let mut tiny = [0xEE; 1];
    let e = encoder.begin(octets, Length::Definite(2), &mut tiny).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::InsufficientSize { required: 2 });
    assert_eq!((tiny, encoder.depth()), ([0xEE], 0));
    let mut buf = [0u8; 8];
    let n = encoder.begin(octets, Length::Definite(2), &mut buf).unwrap();
    let e = encoder.content(&[1, 2], &mut buf[..1]).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::InsufficientSize { required: 2 }));
    assert_eq!(encoder.content(&[1, 2], &mut buf[n..]).unwrap(), 2);
    assert_eq!(encoder.end(&mut []).unwrap(), 0);
    let mut one = [0xEE; 1];
    encoder.begin(id(Tag::SEQUENCE, true), Length::Indefinite, &mut buf).unwrap();
    assert!(encoder.end(&mut one).is_err());
    assert_eq!(one, [0xEE]);
    assert_eq!(encoder.depth(), 1);
    assert_eq!(encoder.end(&mut buf).unwrap(), 2);
}

#[test]
fn interval_sets() {
    const A: IntervalSet = IntervalSet::range(0, 10).union(&IntervalSet::range(20, 30));
    const B: IntervalSet = A.except(&IntervalSet::single(25));
    const C: IntervalSet = A.intersection(&IntervalSet::range(5, 25));
    const D: IntervalSet = IntervalSet::ALL.except(&IntervalSet::range(3, 4));
    const SIZES: IntervalSet = IntervalSet::single(6)
        .union(&IntervalSet::single(8))
        .union(&IntervalSet::single(12))
        .union(&IntervalSet::single(16));
    const OVERLAP: IntervalSet = IntervalSet::range(0, 5).union(&IntervalSet::range(6, 9));
    let members = |s: &IntervalSet| (-2..40).filter(|&v| s.contains(v)).collect::<Vec<i128>>();
    assert_eq!(members(&A), (0..=10).chain(20..=30).collect::<Vec<_>>());
    assert_eq!(members(&B), (0..=10).chain(20..=24).chain(26..=30).collect::<Vec<_>>());
    assert_eq!(members(&C), (5..=10).chain(20..=25).collect::<Vec<_>>());
    assert!(!D.contains(3) && !D.contains(4) && D.contains(2) && D.contains(5));
    assert!(D.contains(i128::MIN) && D.contains(i128::MAX));
    assert_eq!(members(&SIZES), [6, 8, 12, 16]);
    assert_eq!(members(&OVERLAP), (0..=9).collect::<Vec<_>>(), "adjacent intervals merge");
    assert!(IntervalSet::EMPTY.union(&IntervalSet::EMPTY) == IntervalSet::EMPTY);
    assert!(
        IntervalSet::open_range(0, 10).contains(1) && !IntervalSet::open_range(0, 10).contains(0)
    );
    assert!(IntervalSet::range(5, 1) == IntervalSet::EMPTY);
    let sized = OctetString::new(&[0; 8]);
    assert!(check_size(&SIZES, &sized));
    assert!(!check_size(&SIZES, &OctetString::new(&[0; 7])));
    assert!(check_range(&A, &Int::new(&[0x0A]).unwrap()));
    assert!(!check_range(&A, &Int::new(&[0x00, 0xFF]).unwrap()));
    assert!(!check_range(
        &A,
        &Int::new(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    ));
    assert!(check_range(&IntervalSet::range(i128::MIN, 5), &Int::new(&[0x80; 1]).unwrap()));
    assert!(check_alphabet(
        &IntervalSet::range('a' as i128, 'z' as i128),
        &Utf8String::new("hello")
    ));
    assert!(!check_alphabet(
        &IntervalSet::range('a' as i128, 'z' as i128),
        &Utf8String::new("Hello")
    ));
}

proptest! {
    #[test]
    fn interval_algebra_matches_set_semantics(
        a in proptest::collection::vec((0i128..60, 0i128..8), 0..5),
        b in proptest::collection::vec((0i128..60, 0i128..8), 0..5),
    ) {
        let build = |parts: &[(i128, i128)]| {
            parts.iter().fold(IntervalSet::EMPTY, |acc, &(lo, len)| acc.union(&IntervalSet::range(lo, lo + len)))
        };
        let (sa, sb) = (build(&a), build(&b));
        for v in -2..70 {
            let (ia, ib) = (sa.contains(v), sb.contains(v));
            prop_assert_eq!(sa.union(&sb).contains(v), ia || ib);
            prop_assert_eq!(sa.intersection(&sb).contains(v), ia && ib);
            prop_assert_eq!(sa.except(&sb).contains(v), ia && !ib);
        }
    }

    #[test]
    fn stream_encoder_matches_one_shot_encoding(data in proptest::collection::vec(any::<u8>(), 0..400), split in 0usize..400) {
        let value = OctetString::new(&data);
        let mut one_shot = vec![0u8; data.len() + 8];
        let expected = encode_to_slice(&value, &mut one_shot).unwrap().to_vec();
        let mut encoder = StreamEncoder::<2>::new(Rules::Der);
        let mut out = vec![0u8; data.len() + 8];
        let mut used = encoder.begin(id(Tag::OCTET_STRING, false), Length::Definite(data.len() as u64), &mut out).unwrap();
        let cut = split.min(data.len());
        used += encoder.content(&data[..cut], &mut out[used..]).unwrap();
        used += encoder.content(&data[cut..], &mut out[used..]).unwrap();
        used += encoder.end(&mut out[used..]).unwrap();
        prop_assert_eq!(&out[..used], &expected[..]);
    }
}
