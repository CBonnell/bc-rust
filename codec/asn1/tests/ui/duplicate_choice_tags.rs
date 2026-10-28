use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
enum Choice {
    A(u8),
    B(i64),
}

fn main() {}
