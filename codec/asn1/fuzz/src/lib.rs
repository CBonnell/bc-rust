//! Shared helpers for the fuzz targets.

use bouncycastle_asn1::{
    Config, Error, ErrorKind, Event, EventSource, Length, SliceReader, StepKind, Tag, ValueCount,
};

/// An owned, comparable view of the event stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    Header { tag: Tag, constructed: bool, length: Length, offset: u64, depth: usize, raw: Vec<u8> },
    Content(Vec<u8>),
    End { tag: Tag, start: u64, end: u64, depth: usize },
}

pub type Outcome = Result<Vec<Ev>, (ErrorKind, u64)>;

/// Feeds `data` in pieces of the given sizes (cycling) using the documented protocol.
pub fn drive<S: EventSource>(source: &mut S, data: &[u8], chunks: &[usize]) -> Outcome {
    let mut buf: Vec<u8> = Vec::new();
    let mut fed = 0;
    let mut events: Vec<Ev> = Vec::new();
    let mut next_chunk = 0;
    for _ in 0..1_000_000 {
        let eof = fed >= data.len();
        let step = source.step(&buf, eof).map_err(|e| (e.kind().clone(), e.offset()))?;
        let consumed = step.consumed;
        let mut need_more = false;
        match &step.kind {
            StepKind::Event(Event::Header { header, depth }) => events.push(Ev::Header {
                tag: header.tag(),
                constructed: header.constructed(),
                length: header.length(),
                offset: header.offset(),
                depth: *depth,
                raw: header.raw().to_vec(),
            }),
            StepKind::Event(Event::Content(c)) => {
                if let Some(Ev::Content(prev)) = events.last_mut() {
                    prev.extend_from_slice(c);
                } else {
                    events.push(Ev::Content(c.to_vec()));
                }
            }
            StepKind::Event(Event::End { tag, start, end, depth }) => {
                events.push(Ev::End { tag: *tag, start: *start, end: *end, depth: *depth });
            }
            StepKind::Skipped => {}
            StepKind::NeedMore { .. } => need_more = true,
            StepKind::Done => return Ok(events),
        }
        buf.drain(..consumed);
        if need_more {
            assert!(!eof, "NeedMore at eof");
            let size = chunks.get(next_chunk % chunks.len().max(1)).copied().unwrap_or(1).max(1);
            next_chunk += 1;
            let n = size.min(data.len() - fed);
            buf.extend_from_slice(&data[fed..fed + n]);
            fed += n;
        }
    }
    panic!("tokenizer made no progress");
}

/// Reads every TLV recursively through `SliceReader`.
pub fn walk(r: &mut SliceReader<'_>) -> Result<(), Error> {
    r.read_tlv_with(None, |header, contents| {
        if header.constructed() {
            while !contents.is_empty() {
                walk(contents)?;
            }
        } else {
            contents.read_contents()?;
        }
        Ok(())
    })
}

pub fn walk_all(data: &[u8], config: &Config) -> Result<(), (ErrorKind, u64)> {
    let mut r = SliceReader::new(data, config);
    let result = if config.value_count() == ValueCount::Many {
        let mut result = Ok(());
        while !r.is_empty() {
            result = walk(&mut r);
            if result.is_err() {
                break;
            }
        }
        result
    } else {
        walk(&mut r).and_then(|()| r.finish())
    };
    result.map_err(|e| (e.kind().clone(), e.offset()))
}
