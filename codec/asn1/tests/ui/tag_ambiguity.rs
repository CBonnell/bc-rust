use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
struct Ambiguous {
    first: Option<u8>,
    second: u8,
}

fn main() {}
