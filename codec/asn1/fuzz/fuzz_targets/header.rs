#![no_main]

use arbitrary::Arbitrary;
use bouncycastle_asn1::{Class, Config, Header, HeaderParse, Identifier, Length, Rules, Tag};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    bytes: Vec<u8>,
    base: u64,
    ber: bool,
    class: u8,
    number: u16,
    constructed: bool,
    length: Option<u64>,
}

fuzz_target!(|input: Input| {
    let (config, rules) =
        if input.ber { (Config::BER, Rules::Ber) } else { (Config::DER, Rules::Der) };
    // Decoding never panics.
    let _ = Header::decode(&input.bytes, input.base, &config, rules);

    // Encode-then-decode round-trips.
    let class = [Class::Universal, Class::Application, Class::ContextSpecific, Class::Private]
        [usize::from(input.class % 4)];
    let id = Identifier {
        tag: Tag { class, number: u32::from(input.number) % 16_384 },
        constructed: input.constructed,
    };
    let length = input.length.map_or(Length::Indefinite, Length::Definite);
    let mut buf = [0u8; 15];
    let n = id.encode(&mut buf).unwrap();
    let m = length.encode(&mut buf[n..]).unwrap();
    let config = Config::BER.with_max_value_len(u64::MAX);
    match Header::decode(&buf[..n + m], input.base % (1 << 60), &config, Rules::Ber) {
        Ok(HeaderParse::Complete(h)) => {
            assert_eq!(h.id(), id);
            assert_eq!(h.length(), length);
            assert_eq!(h.raw(), &buf[..n + m]);
        }
        // Fixed-form universal types and indefinite primitives are rejected.
        Err(_) => {}
        Ok(HeaderParse::Incomplete { .. }) => panic!("a complete header was reported incomplete"),
    }
});
