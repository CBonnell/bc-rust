#![allow(dead_code)]

use bouncycastle_asn1::{Error, Event, EventSource, Length, StepKind, Tag};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    Header { tag: Tag, constructed: bool, length: Length, offset: u64, depth: usize, raw: Vec<u8> },
    Content(Vec<u8>),
    End { tag: Tag, start: u64, end: u64, depth: usize },
}

/// Feeds `data` to `source` in pieces of `chunk` bytes using the documented compaction
/// protocol, merging adjacent content chunks.
pub fn run<S: EventSource>(source: &mut S, data: &[u8], chunk: usize) -> Result<Vec<Ev>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    let mut fed = 0;
    let mut events: Vec<Ev> = Vec::new();
    let mut guard = 0usize;
    loop {
        guard += 1;
        assert!(guard < 1_000_000, "no progress");
        let eof = fed >= data.len();
        let before = source.position();
        let step = source.step(&buf, eof)?;
        let consumed = step.consumed;
        assert!(consumed <= buf.len());
        let (mut need_more, mut done) = (false, false);
        match &step.kind {
            StepKind::Event(Event::Header { header, depth }) => {
                assert_eq!(header.raw().len(), consumed, "headers are consumed whole");
                events.push(Ev::Header {
                    tag: header.tag(),
                    constructed: header.constructed(),
                    length: header.length(),
                    offset: header.offset(),
                    depth: *depth,
                    raw: header.raw().to_vec(),
                });
            }
            StepKind::Event(Event::Content(c)) => {
                assert!(!c.is_empty());
                if let Some(Ev::Content(prev)) = events.last_mut() {
                    prev.extend_from_slice(c);
                } else {
                    events.push(Ev::Content(c.to_vec()));
                }
            }
            StepKind::Event(Event::End { tag, start, end, depth }) => {
                events.push(Ev::End { tag: *tag, start: *start, end: *end, depth: *depth });
            }
            StepKind::Skipped => assert!(consumed > 0),
            StepKind::NeedMore { at_least } => {
                assert!(!eof, "NeedMore at eof");
                assert!(*at_least >= 1);
                need_more = true;
            }
            StepKind::Done => done = true,
        }
        if done {
            return Ok(events);
        }
        assert_eq!(source.position(), before + consumed as u64);
        buf.drain(..consumed);
        if need_more {
            let n = chunk.min(data.len() - fed);
            buf.extend_from_slice(&data[fed..fed + n]);
            fed += n;
        }
    }
}

pub fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len()).step_by(2).map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap()).collect()
}

pub fn leak(v: Vec<u8>) -> &'static [u8] {
    Box::leak(v.into_boxed_slice())
}

pub fn h(s: &str) -> &'static [u8] {
    leak(hex(s))
}
