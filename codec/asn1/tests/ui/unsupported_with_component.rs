use bouncycastle_asn1::OctetString;
use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
struct Field<'a> {
    #[asn1(constraint = "WITH COMPONENTS { a PRESENT }")]
    value: OctetString<'a>,
}

fn main() {}
