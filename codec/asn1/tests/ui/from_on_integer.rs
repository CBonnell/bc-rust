use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
struct Field {
    #[asn1(constraint = r#"FROM ("a".."z")"#)]
    value: u32,
}

fn main() {}
