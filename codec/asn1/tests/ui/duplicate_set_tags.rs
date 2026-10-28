use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
#[asn1(set)]
struct Members {
    a: u8,
    b: bool,
    c: u16,
}

fn main() {}
