use std::hint::black_box;

use bouncycastle_asn1::*;
use bouncycastle_asn1_derive::Asn1;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

#[derive(Asn1, Debug)]
struct RevokedCertificate<'a> {
    serial: Int<'a>,
    revocation_date: UtcTime,
}

type RevokedCertificates<'a> = SequenceOf<'a, RevokedCertificate<'a>>;

/// A SEQUENCE OF 20-byte serial numbers with revocation dates, like the entries of a large CRL.
fn synthetic_crl(entries: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for i in 0..entries {
        let mut serial = [0u8; 20];
        serial[..8].copy_from_slice(&(i as u64).to_be_bytes());
        serial[0] |= 0x01;
        let entry =
            [vec![0x02, 0x14], serial.to_vec(), vec![0x17, 0x0D], b"260131120000Z".to_vec()]
                .concat();
        body.extend([vec![0x30, entry.len() as u8], entry].concat());
    }
    let len = body.len();
    let header = if len < 128 {
        vec![0x30, len as u8]
    } else {
        let bytes = (len as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        [vec![0x30, 0x80 | (4 - skip) as u8], bytes[skip..].to_vec()].concat()
    };
    [header, body].concat()
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut items = vec![("synthetic-crl-10k".to_string(), synthetic_crl(10_000))];
    if let Ok(dir) = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/benches/corpus")) {
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "der")
                && let Ok(bytes) = std::fs::read(&path)
            {
                items.push((path.file_name().unwrap().to_string_lossy().into_owned(), bytes));
            }
        }
    }
    items
}

fn bench_header(c: &mut Criterion) {
    let header = [0xBF, 0x82, 0x01, 0x82, 0x01, 0x00];
    c.bench_function("header/decode", |b| {
        b.iter(|| Header::decode(black_box(&header), 0, &Config::DER, Rules::Der))
    });
}

fn bench_tokenizer(c: &mut Criterion) {
    let mut group = c.benchmark_group("tokenizer");
    for (name, data) in corpus() {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(&name, |b| {
            b.iter(|| {
                let mut tokenizer = Tokenizer::<32>::new(Config::DER);
                let mut input = black_box(&data[..]);
                let mut events = 0usize;
                loop {
                    let step = tokenizer.step(input, true).unwrap();
                    input = &input[step.consumed..];
                    match step.kind {
                        StepKind::Done => break,
                        StepKind::Event(_) => events += 1,
                        _ => {}
                    }
                }
                events
            })
        });
    }
    group.finish();
}

fn bench_slice_reader(c: &mut Criterion) {
    let crl = synthetic_crl(10_000);
    let mut group = c.benchmark_group("slice_reader");
    group.throughput(Throughput::Bytes(crl.len() as u64));
    group.bench_function("decode-crl-entries", |b| {
        b.iter(|| {
            let mut reader = SliceReader::new(black_box(&crl), &Config::DER);
            let entries = reader.read::<RevokedCertificates>().unwrap();
            entries.iter().map(|e| e.unwrap().serial.as_bytes().len()).sum::<usize>()
        })
    });
    let entries = SliceReader::new(&crl, &Config::DER).read::<RevokedCertificates>().unwrap();
    let mut out = vec![0u8; crl.len()];
    group.bench_function("encode-crl-entries", |b| {
        b.iter(|| encode_to_slice(black_box(&entries), &mut out).unwrap().len())
    });
    group.finish();
}

criterion_group!(benches, bench_header, bench_tokenizer, bench_slice_reader);
criterion_main!(benches);
