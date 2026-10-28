#![no_main]

use bouncycastle_asn1::{ContentCodec, GeneralizedTime, Rules, UtcTime};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    for rules in [Rules::Ber, Rules::Der] {
        let _ = UtcTime::decode_content(bytes, rules);
        let _ = GeneralizedTime::decode_content(bytes, rules);
        let _ = UtcTime::decode_from_copy(bytes, rules);
        let _ = GeneralizedTime::decode_from_copy(bytes, rules);
    }
    // Whatever the BER grammar accepts must satisfy the calendar rules.
    if let Ok(t) = GeneralizedTime::decode_content(bytes, Rules::Ber) {
        assert!(t.month >= 1 && t.month <= 12);
        assert!(t.day >= 1 && t.day <= bouncycastle_asn1::days_in_month(t.year, t.month));
        assert!(t.hour < 24 && t.minute < 60 && t.second < 60 && t.nanos < 1_000_000_000);
    }
});
