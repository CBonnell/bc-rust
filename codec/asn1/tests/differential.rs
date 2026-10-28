//! The tokenizer and `SliceReader` share one set of parsing rules: they must accept and reject
//! the same inputs with the same error kind and offset.

mod common;

use bouncycastle_asn1::*;
use common::run;
use proptest::prelude::*;

type Outcome = Result<(), (ErrorKind, u64)>;

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

fn via_tokenizer(data: &[u8], config: &Config) -> Outcome {
    run(&mut Tokenizer::<32>::new(config.clone()), data, usize::MAX)
        .map(drop)
        .map_err(|e| (e.kind().clone(), e.offset()))
}

fn via_reader(data: &[u8], config: &Config) -> Outcome {
    let mut r = SliceReader::new(data, config);
    let result = if config.value_count() == ValueCount::Many {
        let mut result = Ok(());
        while !r.is_empty() {
            result = walk(&mut r);
            if result.is_err() {
                break;
            }
        }
        result
    } else {
        walk(&mut r).and_then(|()| r.finish())
    };
    result.map_err(|e| (e.kind().clone(), e.offset()))
}

fn small_bytes() -> impl Strategy<Value = Vec<u8>> {
    let byte = prop_oneof![
        3 => 0u8..8,
        2 => prop::sample::select(vec![0x30u8, 0x31, 0x24, 0x04, 0x02, 0x05, 0x80, 0x81, 0x82, 0x00, 0xA0, 0x1F, 0xFF, 0x03]),
        1 => any::<u8>(),
    ];
    proptest::collection::vec(byte, 0..40)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    #[test]
    fn random_bytes_agree(data in small_bytes(), ber in any::<bool>(), many in any::<bool>()) {
        let mut config = if ber { Config::BER } else { Config::DER };
        if many {
            config = config.with_value_count(ValueCount::Many);
        }
        prop_assert_eq!(via_tokenizer(&data, &config), via_reader(&data, &config), "{:02X?}", data);
    }

    #[test]
    fn mutated_trees_agree(tree in tree(4), cuts in 0usize..4, flip in any::<(usize, u8)>(), ber in any::<bool>()) {
        let mut data = render(&tree);
        if cuts == 1 {
            let at = flip.0 % (data.len() + 1);
            data.truncate(at);
        } else if cuts == 2 && !data.is_empty() {
            let at = flip.0 % data.len();
            data[at] = flip.1;
        } else if cuts == 3 {
            data.push(flip.1);
        }
        let config = if ber { Config::BER } else { Config::DER };
        prop_assert_eq!(via_tokenizer(&data, &config), via_reader(&data, &config), "{:02X?}", data);
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
    leaf.prop_recursive(depth, 16, 3, |inner| {
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
            [vec![0x30, body.len() as u8], body].concat()
        }
        Node::Indefinite(kids) => {
            let body: Vec<u8> = kids.iter().flat_map(render).collect();
            [vec![0x30, 0x80], body, vec![0, 0]].concat()
        }
    }
}
