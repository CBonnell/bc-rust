use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
enum Choice {
    Number(u8),
    Flag(bool),
}

#[derive(Asn1)]
struct Wrapper {
    #[asn1(implicit = 0)]
    choice: Choice,
}

fn main() {}
