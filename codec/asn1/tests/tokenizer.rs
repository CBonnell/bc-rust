mod common;

use bouncycastle_asn1::*;
use common::{Ev, hex, run};
use proptest::prelude::*;

fn events(data: &[u8], config: Config) -> Result<Vec<Ev>, Error> {
    run(&mut Tokenizer::<32>::new(config), data, usize::MAX)
}

fn err(data: &[u8], config: Config) -> (ErrorKind, u64) {
    let e = events(data, config).unwrap_err();
    (e.kind().clone(), e.offset())
}

fn header(tag: Tag, constructed: bool, length: Length, offset: u64, depth: usize, raw: &str) -> Ev {
    Ev::Header { tag, constructed, length, offset, depth, raw: hex(raw) }
}

#[test]
fn primitive_and_constructed_streams() {
    let got = events(&hex("30 06 02 01 05 04 01 AA"), Config::DER).unwrap();
    assert_eq!(
        got,
        vec![
            header(Tag::SEQUENCE, true, Length::Definite(6), 0, 0, "30 06"),
            header(Tag::INTEGER, false, Length::Definite(1), 2, 1, "02 01"),
            Ev::Content(vec![5]),
            Ev::End { tag: Tag::INTEGER, start: 2, end: 5, depth: 1 },
            header(Tag::OCTET_STRING, false, Length::Definite(1), 5, 1, "04 01"),
            Ev::Content(vec![0xAA]),
            Ev::End { tag: Tag::OCTET_STRING, start: 5, end: 8, depth: 1 },
            Ev::End { tag: Tag::SEQUENCE, start: 0, end: 8, depth: 0 },
        ]
    );
}

#[test]
fn zero_length_primitive_has_no_content_event() {
    let got = events(&hex("05 00"), Config::DER).unwrap();
    assert_eq!(
        got,
        vec![
            header(Tag::NULL, false, Length::Definite(0), 0, 0, "05 00"),
            Ev::End { tag: Tag::NULL, start: 0, end: 2, depth: 0 },
        ]
    );
}

#[test]
fn indefinite_end_consumes_eoc_and_nested_ends_come_innermost_first() {
    let got = events(&hex("30 80 30 80 05 00 00 00 00 00"), Config::BER).unwrap();
    let ends: Vec<_> = got.iter().filter(|e| matches!(e, Ev::End { .. })).collect();
    assert_eq!(
        ends,
        vec![
            &Ev::End { tag: Tag::NULL, start: 4, end: 6, depth: 2 },
            &Ev::End { tag: Tag::SEQUENCE, start: 2, end: 8, depth: 1 },
            &Ev::End { tag: Tag::SEQUENCE, start: 0, end: 10, depth: 0 },
        ]
    );
}

#[test]
fn definite_ends_at_same_byte_are_one_per_step() {
    let data = hex("30 04 30 02 05 00");
    let mut t = Tokenizer::<32>::new(Config::DER);
    let mut buf = &data[..];
    let mut kinds = Vec::new();
    loop {
        let step = t.step(buf, true).unwrap();
        buf = &buf[step.consumed..];
        match step.kind {
            StepKind::Event(Event::End { depth, .. }) => kinds.push((depth, step.consumed)),
            StepKind::Done => break,
            _ => {}
        }
    }
    assert_eq!(kinds, vec![(2, 0), (1, 0), (0, 0)]);
}

#[test]
fn multiple_values() {
    let many = Config::DER.with_value_count(ValueCount::Many);
    let got = events(&hex("05 00 05 00"), many.clone()).unwrap();
    assert_eq!(got.iter().filter(|e| matches!(e, Ev::End { .. })).count(), 2);
    assert!(events(&[], many).unwrap().is_empty());
    // One: empty input is an incomplete value; extra bytes are trailing data.
    assert_eq!(err(&[], Config::DER), (ErrorKind::Truncated, 0));
    assert_eq!(err(&hex("05 00 05 00"), Config::DER), (ErrorKind::TrailingData, 2));
}

#[test]
fn done_is_returned_repeatedly() {
    let mut t = Tokenizer::<32>::new(Config::DER);
    let data = hex("05 00");
    let mut used = 0;
    for _ in 0..3 {
        used += t.step(&data[used..], true).unwrap().consumed;
    }
    assert_eq!(used, 2);
    for _ in 0..2 {
        let s = t.step(&[], true).unwrap();
        assert_eq!((s.consumed, s.kind), (0, StepKind::Done));
    }
}

#[test]
fn nesting_invariants() {
    // Child extends past definite parent.
    assert_eq!(
        err(&hex("30 02 04 05 00 00 00 00 00"), Config::DER),
        (ErrorKind::ChildOverrunsParent, 2)
    );
    // Header straddles the parent's end.
    assert_eq!(err(&hex("30 01 04 05"), Config::DER), (ErrorKind::ChildOverrunsParent, 2));
    // Indefinite child inside a definite parent that ends before its EOC.
    assert_eq!(
        err(&hex("30 03 30 80 05 00 00 00"), Config::BER),
        (ErrorKind::ChildOverrunsParent, 4)
    );
    // Definite child of an indefinite parent must still fit the definite grandparent.
    assert_eq!(
        err(&hex("30 05 30 80 04 09 00 00"), Config::BER),
        (ErrorKind::ChildOverrunsParent, 4)
    );
    // End-of-contents outside an indefinite value.
    assert_eq!(err(&hex("00 00"), Config::BER), (ErrorKind::UnexpectedEoc, 0));
    assert_eq!(err(&hex("30 02 00 00"), Config::BER), (ErrorKind::UnexpectedEoc, 2));
    assert_eq!(err(&hex("30 80 20 00"), Config::BER), (ErrorKind::UnexpectedEoc, 2));
    // Everything well-formed passes, whatever its tag.
    assert!(events(&hex("DF 81 00 01 AA"), Config::DER).is_ok());
}

#[test]
fn depth_limit() {
    let mut data = Vec::new();
    for _ in 0..4 {
        data.extend([0x30, 0x80]);
    }
    let mut t = Tokenizer::<3>::new(Config::BER);
    let e = run(&mut t, &data, usize::MAX).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::DepthExceeded, 6));
    // Exactly DEPTH levels is fine.
    let ok = hex("30 80 30 80 05 00 00 00 00 00");
    assert!(run(&mut Tokenizer::<3>::new(Config::BER), &ok, usize::MAX).is_ok());
    assert!(run(&mut Tokenizer::<2>::new(Config::BER), &ok, usize::MAX).is_err());
}

#[test]
fn errors_are_sticky() {
    let mut t = Tokenizer::<32>::new(Config::DER);
    let e = t.step(&[0x04, 0xFF], true).unwrap_err();
    assert_eq!(t.step(&[], true).unwrap_err(), e);
}

#[test]
fn truncation() {
    assert_eq!(err(&hex("04 05 01 02"), Config::DER), (ErrorKind::Truncated, 4));
    assert_eq!(err(&hex("30 04 02 01"), Config::DER), (ErrorKind::Truncated, 4));
    assert_eq!(err(&hex("30 80 05 00"), Config::BER), (ErrorKind::Truncated, 4));
    assert_eq!(err(&hex("04 82 01"), Config::DER), (ErrorKind::Truncated, 3));
    // eof = false never errors on truncation.
    let mut t = Tokenizer::<32>::new(Config::DER);
    let data = hex("04 82 01");
    let s = t.step(&data, false).unwrap();
    assert_eq!((s.consumed, s.kind), (0, StepKind::NeedMore { at_least: 4 }));
}

#[test]
fn header_straddling_input_is_never_partially_consumed() {
    let data = hex("BF 82 01 82 01 00");
    let mut data = data;
    data.extend(vec![0u8; 256]);
    for cut in 0..6 {
        let mut t = Tokenizer::<32>::new(Config::BER);
        let s = t.step(&data[..cut], false).unwrap();
        assert_eq!(s.consumed, 0);
        assert!(matches!(s.kind, StepKind::NeedMore { at_least } if at_least > cut));
    }
}

#[test]
fn needmore_for_content_is_one_byte() {
    let mut t = Tokenizer::<32>::new(Config::DER);
    let data = hex("04 03 01 02 03");
    let s = t.step(&data[..2], false).unwrap();
    assert!(matches!(s.kind, StepKind::Event(Event::Header { .. })));
    let s = t.step(&[], false).unwrap();
    assert_eq!(s.kind, StepKind::NeedMore { at_least: 1 });
    let s = t.step(&data[2..4], false).unwrap();
    assert_eq!((s.consumed, s.kind), (2, StepKind::Event(Event::Content(&data[2..4]))));
}

#[test]
fn gather_content() {
    let data = hex("04 04 01 02 03 04");
    let mut t = Tokenizer::<32>::new(Config::DER);
    let s = t.step(&data, false).unwrap();
    assert_eq!(s.consumed, 2);
    t.gather_content().unwrap();
    let s = t.step(&data[2..4], false).unwrap();
    assert_eq!((s.consumed, s.kind), (0, StepKind::NeedMore { at_least: 4 }));
    let s = t.step(&data[2..], false).unwrap();
    assert_eq!((s.consumed, s.kind), (4, StepKind::Event(Event::Content(&data[2..]))));
    assert!(matches!(t.step(&[], false).unwrap().kind, StepKind::Event(Event::End { .. })));
    // Gather on a constructed value, or twice, is an invalid state.
    let mut t = Tokenizer::<32>::new(Config::DER);
    t.step(&hex("30 00"), false).unwrap();
    assert_eq!(t.gather_content().unwrap_err().kind(), &ErrorKind::InvalidState);
}

#[test]
fn state_dependent_calls_need_a_header() {
    let mut t = Tokenizer::<32>::new(Config::DER);
    for e in [t.gather_content(), t.skip_content(), t.tighten_rules(Rules::Der)] {
        assert_eq!(e.unwrap_err().kind(), &ErrorKind::InvalidState);
    }
    let data = hex("04 01 AA");
    t.step(&data, false).unwrap();
    t.step(&data[2..], false).unwrap();
    assert_eq!(t.skip_content().unwrap_err().kind(), &ErrorKind::InvalidState);
}

#[test]
fn skip_definite_and_indefinite() {
    for (data, config) in [
        (hex("30 06 30 04 04 02 01 02 05 00"), Config::DER),
        (hex("30 80 30 80 04 02 01 02 00 00 04 02 03 04 00 00 05 00"), Config::BER),
        (hex("30 80 24 80 04 01 AA 00 00 00 00 05 00"), Config::BER),
    ] {
        let many = config.with_value_count(ValueCount::Many);
        let mut t = Tokenizer::<32>::new(many);
        let mut input = &data[..];
        let step = t.step(input, true).unwrap();
        input = &input[step.consumed..];
        t.skip_content().unwrap();
        let mut skipped = 0;
        let end = loop {
            let step = t.step(input, true).unwrap();
            input = &input[step.consumed..];
            match step.kind {
                StepKind::Skipped => skipped += step.consumed,
                StepKind::Event(e) => break e,
                other => panic!("{other:?}"),
            }
        };
        assert!(matches!(end, Event::End { depth: 0, tag: Tag::SEQUENCE, .. }), "{end:?}");
        assert!(skipped > 0);
        // Tokenizing continues after the skipped value.
        let step = t.step(input, true).unwrap();
        assert!(matches!(step.kind, StepKind::Event(Event::Header { .. })) || data.len() < 10);
        let _ = skipped;
    }
}

#[test]
fn skip_errors() {
    // The skipped indefinite value is still structurally checked.
    let mut t = Tokenizer::<32>::new(Config::BER);
    let data = hex("30 80 04 05 01");
    let s = t.step(&data, true).unwrap();
    t.skip_content().unwrap();
    let mut input = &data[s.consumed..];
    let e = loop {
        match t.step(input, true) {
            Ok(s) => input = &input[s.consumed..],
            Err(e) => break e,
        }
    };
    assert_eq!(e.kind(), &ErrorKind::Truncated);
    // A definite child overrunning the grandparent during skip.
    let mut t = Tokenizer::<32>::new(Config::BER);
    let data = hex("30 05 30 80 04 09 00 00");
    let mut input = &data[..];
    for _ in 0..2 {
        let s = t.step(input, true).unwrap();
        input = &input[s.consumed..];
    }
    t.skip_content().unwrap();
    let e = t.step(input, true).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::ChildOverrunsParent);
}

#[test]
fn tighten_rules_applies_to_subtree_and_reverts() {
    // BER SEQUENCE holding a SET that is tightened to DER; its non-minimal child length fails,
    // while the sibling after the SET is still read under BER.
    let ok = hex("30 80 31 03 04 81 00 04 81 00 00 00");
    let mut t = Tokenizer::<32>::new(Config::BER);
    let mut input = &ok[..];
    let run_until =
        |t: &mut Tokenizer<32>, input: &mut &[u8], tighten: bool| -> Result<(), Error> {
            loop {
                let s = t.step(input, true)?;
                *input = &input[s.consumed..];
                match s.kind {
                    StepKind::Event(Event::Header { header, .. })
                        if tighten && header.tag() == Tag::SET =>
                    {
                        t.tighten_rules(Rules::Der)?;
                        assert_eq!(t.rules(), Rules::Der);
                    }
                    StepKind::Done => return Ok(()),
                    _ => {}
                }
            }
        };
    // Without tightening this is valid BER.
    let mut t2 = Tokenizer::<32>::new(Config::BER);
    let mut input2 = &ok[..];
    assert!(run_until(&mut t2, &mut input2, false).is_ok());
    let e = run_until(&mut t, &mut input, true).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (&ErrorKind::NonMinimalLength, 5));

    // Reverts at End: the sibling uses BER again.
    let data = hex("30 80 31 00 04 81 00 00 00");
    let mut t = Tokenizer::<32>::new(Config::BER);
    let mut input = &data[..];
    assert!(run_until(&mut t, &mut input, true).is_ok());

    // Loosening is an error.
    let mut t = Tokenizer::<32>::new(Config::DER);
    t.step(&hex("30 00"), true).unwrap();
    assert_eq!(t.tighten_rules(Rules::Ber).unwrap_err().kind(), &ErrorKind::RulesLoosened);
}

#[test]
fn deviations_start_empty() {
    assert!(Tokenizer::<32>::new(Config::DER).deviations().is_empty());
}

fn chunked(data: &[u8], config: &Config) -> Vec<Result<Vec<Ev>, (ErrorKind, u64)>> {
    [1usize, 2, 3, 5, 7, 16, usize::MAX]
        .into_iter()
        .map(|chunk| {
            run(&mut Tokenizer::<8>::new(config.clone()), data, chunk)
                .map_err(|e| (e.kind().clone(), e.offset()))
        })
        .collect()
}

#[test]
fn chunking_does_not_change_the_result() {
    let samples = [
        "30 35 31 0B 30 09 06 03 55 04 06 13 02 55 53 31 15 30 13 06 03 55 04 0A 13 0C 45 78 61 6D 70 6C 65 20 49 6E 63 2E 31 0F 30 0D 06 03 55 04 03 13 06 55 73 65 72 20 31",
        "30 80 24 80 04 02 01 02 04 82 00 02 03 04 00 00 00 00",
        "BF 82 01 05 AA AA AA AA AA",
        "30 03 04 05 00",
        "04 81 05",
    ];
    for s in samples {
        for config in [Config::DER, Config::BER] {
            let results = chunked(&hex(s), &config);
            assert!(results.windows(2).all(|w| w[0] == w[1]), "{s}: {results:?}");
        }
    }
}

proptest! {
    #[test]
    fn chunked_equals_whole(data in proptest::collection::vec(any::<u8>(), 0..64), ber in any::<bool>()) {
        let config = if ber { Config::BER } else { Config::DER };
        let results = chunked(&data, &config);
        prop_assert!(results.windows(2).all(|w| w[0] == w[1]), "{:?}", results);
    }

    #[test]
    fn structured_inputs_chunk_identically(tree in tree(3)) {
        let data = render(&tree);
        let results = chunked(&data, &Config::BER);
        prop_assert!(results.windows(2).all(|w| w[0] == w[1]));
        prop_assert!(results[0].is_ok(), "{:?}", results[0]);
    }
}

#[derive(Debug, Clone)]
enum Node {
    Leaf(Vec<u8>),
    Definite(Vec<Node>),
    Indefinite(Vec<Node>),
}

fn tree(depth: u32) -> impl Strategy<Value = Node> {
    let leaf = proptest::collection::vec(any::<u8>(), 0..6).prop_map(Node::Leaf);
    leaf.prop_recursive(depth, 12, 3, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..3).prop_map(Node::Definite),
            proptest::collection::vec(inner, 0..3).prop_map(Node::Indefinite),
        ]
    })
}

fn render(node: &Node) -> Vec<u8> {
    match node {
        Node::Leaf(b) => [vec![0x04, b.len() as u8], b.clone()].concat(),
        Node::Definite(kids) => {
            let body: Vec<u8> = kids.iter().flat_map(render).collect();
            let len = if body.len() < 128 {
                vec![body.len() as u8]
            } else {
                vec![0x82, (body.len() >> 8) as u8, body.len() as u8]
            };
            [vec![0x30], len, body].concat()
        }
        Node::Indefinite(kids) => {
            let body: Vec<u8> = kids.iter().flat_map(render).collect();
            [vec![0x30, 0x80], body, vec![0, 0]].concat()
        }
    }
}

#[test]
fn one_value_waits_for_eof_before_done() {
    let mut t = Tokenizer::<32>::new(Config::DER);
    let data = hex("05 00");
    let mut used = 0;
    for _ in 0..3 {
        used += t.step(&data[used..], false).unwrap().consumed;
    }
    assert_eq!(t.step(&[], false).unwrap().kind, StepKind::NeedMore { at_least: 1 });
    assert_eq!(t.step(&[0], false).unwrap_err().kind(), &ErrorKind::TrailingData);
}

#[test]
fn gather_survives_need_more_across_many_chunks() {
    let data = hex("04 04 01 02 03 04");
    let mut t = Tokenizer::<32>::new(Config::DER);
    t.step(&data, false).unwrap();
    t.gather_content().unwrap();
    for have in 0..4 {
        let s = t.step(&data[2..2 + have], false).unwrap();
        assert_eq!((s.consumed, s.kind), (0, StepKind::NeedMore { at_least: 4 }));
    }
    let s = t.step(&data[2..], false).unwrap();
    assert_eq!(s.kind, StepKind::Event(Event::Content(&data[2..])));
}

#[test]
fn end_of_contents_is_exactly_two_zero_octets() {
    for data in ["E3 80 E3 80 00 00 00 81 00", "30 80 00 81 00", "30 80 00 82 00 00"] {
        let (kind, offset) = err(&hex(data), Config::BER);
        assert_eq!(kind, ErrorKind::UnexpectedEoc, "{data}");
        assert!(offset > 0);
    }
    assert!(events(&hex("E3 80 E3 80 00 00 00 00"), Config::BER).is_ok());
}
