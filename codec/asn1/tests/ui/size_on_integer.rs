use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
struct Field {
    #[asn1(constraint = "SIZE (1..4)")]
    value: u32,
}

fn main() {}
