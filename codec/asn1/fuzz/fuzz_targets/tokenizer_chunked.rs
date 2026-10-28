#![no_main]

use arbitrary::Arbitrary;
use bouncycastle_asn1::{Config, Tokenizer, ValueCount};
use bouncycastle_asn1_fuzz::drive;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    chunks: Vec<u8>,
    ber: bool,
    many: bool,
}

fuzz_target!(|input: Input| {
    let mut config = if input.ber { Config::BER } else { Config::DER };
    if input.many {
        config = config.with_value_count(ValueCount::Many);
    }
    let whole = drive(&mut Tokenizer::<16>::new(config.clone()), &input.data, &[usize::MAX]);
    let chunks: Vec<usize> = input.chunks.iter().map(|&c| usize::from(c % 17)).collect();
    let chunked = drive(&mut Tokenizer::<16>::new(config), &input.data, &chunks);
    assert_eq!(whole, chunked);
});
