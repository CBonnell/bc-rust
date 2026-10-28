use bouncycastle_asn1::OctetString;
use bouncycastle_asn1_derive::Asn1;

#[derive(Asn1)]
struct Field<'a> {
    #[asn1(constraint = "SIZE (1..4) | 5..9")]
    value: OctetString<'a>,
}

fn main() {}
