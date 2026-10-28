#![no_main]

use bouncycastle_asn1::{Config, SliceReader};
use der::{Decode, Reader, Tagged};
use libfuzzer_sys::fuzz_target;

/// Walks SEQUENCEs and SETs the way `der` does: everything else is a leaf.
fn der_accepts(input: &[u8], depth: usize) -> bool {
    if depth > 20 {
        return false;
    }
    let mut reader = match der::SliceReader::new(input) {
        Ok(r) => r,
        Err(_) => return false,
    };
    while !reader.is_finished() {
        let Ok(any) = der::AnyRef::decode(&mut reader) else { return false };
        if matches!(any.tag(), der::Tag::Sequence | der::Tag::Set)
            && !der_accepts(any.value(), depth + 1)
        {
            return false;
        }
    }
    true
}

fn ours(r: &mut SliceReader<'_>, depth: usize) -> Result<(), bouncycastle_asn1::Error> {
    r.read_tlv_with(None, |header, contents| {
        let tag = header.tag();
        let recurse = header.constructed()
            && tag.class == bouncycastle_asn1::Class::Universal
            && matches!(tag.number, 16 | 17);
        if recurse {
            while !contents.is_empty() {
                ours(contents, depth + 1)?;
            }
        } else {
            // `der` treats every other value, constructed or not, as an opaque leaf.
            contents.read_contents().map(drop)?;
        }
        Ok(())
    })
}

fuzz_target!(|input: &[u8]| {
    let Ok(any) = der::AnyRef::from_der(input) else { return };
    if !der_accepts(input, 0) {
        return;
    }
    let _ = any;
    let mut r = SliceReader::new(input, &Config::DER);
    // Where `der` accepts DER, so do we; differences are reviewed from the crash artifact.
    if let Err(e) = ours(&mut r, 0).and_then(|()| r.finish()) {
        panic!("der accepts {input:02X?} but we reject it: {e}");
    }
});
