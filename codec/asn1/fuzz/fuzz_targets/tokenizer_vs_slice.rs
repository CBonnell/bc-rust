#![no_main]

use arbitrary::Arbitrary;
use bouncycastle_asn1::{Config, Tokenizer, ValueCount};
use bouncycastle_asn1_fuzz::{drive, walk_all};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    ber: bool,
    many: bool,
}

fuzz_target!(|input: Input| {
    let mut config = if input.ber { Config::BER } else { Config::DER };
    if input.many {
        config = config.with_value_count(ValueCount::Many);
    }
    let tokenizer =
        drive(&mut Tokenizer::<32>::new(config.clone()), &input.data, &[usize::MAX]).map(drop);
    let slice = walk_all(&input.data, &config);
    assert_eq!(tokenizer, slice, "{:02X?}", input.data);
});
