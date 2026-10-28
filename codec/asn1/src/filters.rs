//! Layer 3: event filters.
//!
//! Filters wrap any [`EventSource`] and implement it themselves, so they stack. Put
//! [`ContentValidator`] closest to the tokenizer and [`StringReassembler`] outside it:
//! `StringReassembler::new(ContentValidator::new(Tokenizer::<32>::new(config)))`.

use crate::header::is_string_type;
use crate::primitives::strings::{
    BmpString, Ia5String, NumericString, PrintableString, UniversalString, VisibleString,
};
use crate::primitives::validate_content;
use crate::{
    Class, ContentCodec, Deviations, Error, ErrorKind, Event, EventSource, GeneralizedTime, Rules,
    Step, StepKind, Tag, UtcTime, ValueError,
};

#[derive(Clone, Debug)]
struct StringCheck {
    tag: Tag,
    depth: usize,
    carry: [u8; 4],
    carry_len: usize,
    want: usize,
}

impl StringCheck {
    fn new(tag: Tag, depth: usize) -> Self {
        StringCheck { tag, depth, carry: [0; 4], carry_len: 0, want: 0 }
    }

    fn push_carry(&mut self, b: u8) {
        if let Some(slot) = self.carry.get_mut(self.carry_len) {
            *slot = b;
            self.carry_len += 1;
        }
    }

    fn carried(&self) -> &[u8] {
        self.carry.get(..self.carry_len).unwrap_or(&[])
    }

    /// Checks `chunk`; on failure returns the error and the index of the offending byte.
    fn feed(&mut self, chunk: &[u8]) -> Result<(), (ValueError, usize)> {
        for (i, &b) in chunk.iter().enumerate() {
            let checked = match self.tag.number {
                12 => self.feed_utf8(b),
                18 => check_byte(NumericString::is_allowed_byte, b),
                19 => check_byte(PrintableString::is_allowed_byte, b),
                22 => check_byte(Ia5String::is_allowed_byte, b),
                26 => check_byte(VisibleString::is_allowed_byte, b),
                28 => self.feed_units(b, 4),
                30 => self.feed_units(b, 2),
                _ => Ok(()),
            };
            checked.map_err(|e| (e, i))?;
        }
        Ok(())
    }

    fn feed_utf8(&mut self, b: u8) -> Result<(), ValueError> {
        if self.carry_len == 0 {
            self.want = match b {
                0x00..=0x7F => return Ok(()),
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => return Err(ValueError::InvalidCharacterEncoding),
            };
        } else if b & 0xC0 != 0x80 {
            return Err(ValueError::InvalidCharacterEncoding);
        }
        self.push_carry(b);
        if self.carry_len == self.want {
            core::str::from_utf8(self.carried())
                .map_err(|_| ValueError::InvalidCharacterEncoding)?;
            self.carry_len = 0;
        }
        Ok(())
    }

    fn feed_units(&mut self, b: u8, width: usize) -> Result<(), ValueError> {
        self.push_carry(b);
        if self.carry_len == width {
            match *self.carried() {
                [a, b] => BmpString::decode_unit([a, b]).map(drop)?,
                [a, b, c, d] => UniversalString::decode_unit([a, b, c, d]).map(drop)?,
                _ => {}
            }
            self.carry_len = 0;
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), ValueError> {
        let incomplete = match self.tag.number {
            12 => self.carry_len != 0,
            _ => false,
        };
        if incomplete {
            return Err(ValueError::InvalidCharacterEncoding);
        }
        if matches!(self.tag.number, 28 | 30) && self.carry_len != 0 {
            return Err(ValueError::InvalidLength);
        }
        Ok(())
    }
}

fn check_byte(allowed: fn(u8) -> bool, b: u8) -> Result<(), ValueError> {
    if allowed(b) { Ok(()) } else { Err(ValueError::NotInAlphabet) }
}

#[derive(Clone, Debug)]
struct TimeCopy {
    tag: Tag,
    depth: usize,
    buf: [u8; 32],
    len: usize,
}

impl TimeCopy {
    fn max_len(&self) -> usize {
        if self.tag == Tag::UTC_TIME {
            <UtcTime as ContentCodec>::MAX_COPY_LEN
        } else {
            <GeneralizedTime as ContentCodec>::MAX_COPY_LEN
        }
    }

    /// Copies `chunk`; on overflow returns the index of the first byte that doesn't fit.
    fn push(&mut self, chunk: &[u8]) -> Result<(), usize> {
        let end = self.len + chunk.len();
        let first_overflow = self.max_len() - self.len;
        let dst = if end <= self.max_len() { self.buf.get_mut(self.len..end) } else { None };
        dst.ok_or(first_overflow)?.copy_from_slice(chunk);
        self.len = end;
        Ok(())
    }

    fn finish(&self, rules: Rules) -> Result<(), ValueError> {
        let content = self.buf.get(..self.len).unwrap_or(&[]);
        if self.tag == Tag::UTC_TIME {
            UtcTime::decode_from_copy(content, rules).map(drop)
        } else {
            GeneralizedTime::decode_from_copy(content, rules).map(drop)
        }
    }
}

/// Tracks the unused-bits octet of each primitive BIT STRING segment.
#[derive(Clone, Debug, Default)]
struct BitSegments {
    open_depth: Option<usize>,
    awaiting_unused: bool,
    unused: u8,
    data_len: u64,
    last_octet: u8,
    previous_unused: u8,
}

impl BitSegments {
    fn open(&mut self, depth: usize) {
        self.open_depth = Some(depth);
        self.awaiting_unused = true;
        self.unused = 0;
        self.data_len = 0;
    }

    /// Consumes the unused-bits octet if it leads `chunk` and returns the data octets.
    fn strip<'c>(&mut self, chunk: &'c [u8]) -> Result<&'c [u8], ValueError> {
        let data = if self.awaiting_unused {
            let (&unused, data) = chunk.split_first().ok_or(ValueError::BitStringUnusedBits)?;
            if unused > 7 {
                return Err(ValueError::BitStringUnusedBits);
            }
            self.awaiting_unused = false;
            self.unused = unused;
            data
        } else {
            chunk
        };
        if let Some(&last) = data.last() {
            self.last_octet = last;
        }
        self.data_len += crate::util::saturating_to_u64(data.len());
        Ok(data)
    }

    fn close(&mut self, rules: Rules) -> Result<(), ValueError> {
        self.open_depth = None;
        if self.awaiting_unused || (self.data_len == 0 && self.unused != 0) {
            return Err(ValueError::BitStringUnusedBits);
        }
        if rules == Rules::Der && self.unused > 0 && self.last_octet & ((1 << self.unused) - 1) != 0
        {
            return Err(ValueError::BitStringPaddingNotZero);
        }
        self.previous_unused = self.unused;
        Ok(())
    }
}

/// Validates universal-tagged primitive contents as they pass, under the active rules of the
/// value.
///
/// - BOOLEAN, INTEGER, ENUMERATED, NULL, OID and RELATIVE-OID are gathered whole and checked
///   by their [`ContentCodec`]; the caller's buffer must hold the largest such value.
/// - UTCTime and GeneralizedTime contents are copied into a 32-byte array across every segment
///   and checked at the outer `End`.
/// - Strings are checked incrementally: UTF-8 carries up to 3 bytes of state across chunks,
///   character sets are checked per byte, and BMPString and UniversalString lengths at the end.
/// - BIT STRING checks the unused-bits octet of each segment and, under DER, the padding.
/// - Context-specific, application and private tags pass through unchecked.
///
/// SET OF ordering is not checked while streaming.
#[derive(Debug)]
pub struct ContentValidator<S: EventSource> {
    inner: S,
    pending_gather: Option<(Tag, u64)>,
    gathering: Option<(Tag, u64)>,
    string: Option<StringCheck>,
    time: Option<TimeCopy>,
    bits: Option<(usize, BitSegments)>,
    rules: Rules,
}

impl<S: EventSource> ContentValidator<S> {
    /// Wraps `inner`.
    pub fn new(inner: S) -> Self {
        let rules = inner.rules();
        ContentValidator {
            inner,
            pending_gather: None,
            gathering: None,
            string: None,
            time: None,
            bits: None,
            rules,
        }
    }

    /// Unwraps the inner source.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn on_header(&mut self, header: &crate::Header<'_>, depth: usize) -> Result<(), Error> {
        self.rules = self.inner.rules();
        let tag = header.tag();
        if let Some(expected) = self.time.as_ref().map(|t| t.tag).or(self.outer_string_tag()) {
            if tag != expected {
                let kind = ErrorKind::UnexpectedTag { expected: Some(expected), found: tag };
                return Err(Error::new(kind, header.offset()));
            }
            if let Some((_, bits)) = self.bits.as_mut() {
                if bits.previous_unused != 0 {
                    return Err(Error::value(ValueError::BitStringUnusedBits, header.offset()));
                }
                if !header.constructed() {
                    bits.open(depth);
                }
            }
            return Ok(());
        }
        if tag.class != Class::Universal {
            return Ok(());
        }
        match tag.number {
            1 | 2 | 5 | 6 | 10 | 13 => {
                self.pending_gather = Some((tag, header.content_offset()));
            }
            23 | 24 => {
                self.time = Some(TimeCopy { tag, depth, buf: [0; 32], len: 0 });
            }
            3 => {
                let mut bits = BitSegments::default();
                if !header.constructed() {
                    bits.open(depth);
                }
                self.bits = Some((depth, bits));
                self.string = Some(StringCheck::new(tag, depth));
            }
            12 | 18 | 19 | 22 | 26 | 28 | 30 => {
                self.string = Some(StringCheck::new(tag, depth));
            }
            _ => {}
        }
        Ok(())
    }

    fn outer_string_tag(&self) -> Option<Tag> {
        self.string.as_ref().map(|s| s.tag)
    }

    fn on_content(&mut self, chunk: &[u8]) -> Result<(), Error> {
        self.rules = self.inner.rules();
        let base =
            self.inner.position().saturating_sub(crate::util::saturating_to_u64(chunk.len()));
        let at = |i: usize| base.saturating_add(crate::util::saturating_to_u64(i));
        if let Some((tag, content_offset)) = self.gathering.take() {
            return validate_content(tag, chunk, self.rules)
                .map_err(|e| Error::value(e, content_offset));
        }
        if let Some(time) = self.time.as_mut() {
            return time.push(chunk).map_err(|i| Error::value(ValueError::InvalidLength, at(i)));
        }
        let data = match self.bits.as_mut() {
            Some((_, bits)) => bits.strip(chunk).map_err(|e| Error::value(e, base))?,
            None => chunk,
        };
        let skipped = chunk.len() - data.len();
        if let Some(string) = self.string.as_mut() {
            string.feed(data).map_err(|(e, i)| Error::value(e, at(skipped + i)))?;
        }
        Ok(())
    }

    fn on_end(&mut self, start: u64, depth: usize) -> Result<(), Error> {
        let rules = self.rules;
        if let Some((tag, content_offset)) = self.gathering.take() {
            validate_content(tag, &[], rules).map_err(|e| Error::value(e, content_offset))?;
        }
        if let Some((_, bits)) = self.bits.as_mut()
            && bits.open_depth == Some(depth)
        {
            bits.close(rules).map_err(|e| Error::value(e, start))?;
        }
        if self.time.as_ref().is_some_and(|t| t.depth == depth)
            && let Some(time) = self.time.take()
        {
            time.finish(rules).map_err(|e| Error::value(e, start))?;
        }
        if self.string.as_ref().is_some_and(|s| s.depth == depth)
            && let Some(string) = self.string.take()
        {
            string.finish().map_err(|e| Error::value(e, start))?;
            self.bits = None;
        }
        Ok(())
    }
}

impl<S: EventSource> EventSource for ContentValidator<S> {
    fn step<'a>(&mut self, input: &'a [u8], eof: bool) -> Result<Step<'a>, Error> {
        if let Some(pending) = self.pending_gather.take() {
            self.inner.gather_content()?;
            self.gathering = Some(pending);
        }
        let step = self.inner.step(input, eof)?;
        if let StepKind::Event(event) = &step.kind {
            match event {
                Event::Header { header, depth } => self.on_header(header, *depth)?,
                Event::Content(chunk) => self.on_content(chunk)?,
                Event::End { start, depth, .. } => self.on_end(*start, *depth)?,
            }
        }
        Ok(step)
    }

    fn gather_content(&mut self) -> Result<(), Error> {
        self.pending_gather = None;
        self.inner.gather_content()
    }

    fn skip_content(&mut self) -> Result<(), Error> {
        self.pending_gather = None;
        self.inner.skip_content()
    }

    fn tighten_rules(&mut self, rules: Rules) -> Result<(), Error> {
        self.inner.tighten_rules(rules)?;
        self.rules = self.inner.rules();
        Ok(())
    }

    fn position(&self) -> u64 {
        self.inner.position()
    }

    fn depth(&self) -> usize {
        self.inner.depth()
    }

    fn deviations(&self) -> &Deviations {
        self.inner.deviations()
    }

    fn rules(&self) -> Rules {
        self.inner.rules()
    }
}

#[derive(Clone, Debug)]
struct Outer {
    tag: Tag,
    depth: usize,
}

/// Under BER, collapses a constructed string into one logical primitive `Header`, a run of
/// `Content` chunks and `End`. Primitive strings pass through; constructed strings are already
/// rejected under DER.
///
/// It applies to every universal string type: OCTET STRING, BIT STRING, all character strings,
/// and UTCTime and GeneralizedTime. Every segment must be a primitive or constructed encoding of
/// the same universal type, nested to any depth within the stack limit.
///
/// For BIT STRING, every segment except the last must have zero unused bits. The Content chunks
/// of a BIT STRING, reassembled or not, carry the data octets alone with every unused-bits
/// octet removed; after the `End`, [`last_unused_bits`](StringReassembler::last_unused_bits)
/// reports the count. The logical `Header` keeps the original raw bytes.
#[derive(Debug)]
pub struct StringReassembler<S: EventSource> {
    inner: S,
    outer: Option<Outer>,
    bits: BitSegments,
    last_unused: Option<u8>,
}

impl<S: EventSource> StringReassembler<S> {
    /// Wraps `inner`.
    pub fn new(inner: S) -> Self {
        StringReassembler { inner, outer: None, bits: BitSegments::default(), last_unused: None }
    }

    /// Unwraps the inner source.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// The unused-bits count of the BIT STRING that last ended, or `None` if the last value
    /// wasn't a BIT STRING or hasn't ended.
    pub fn last_unused_bits(&self) -> Option<u8> {
        self.last_unused
    }

    fn is_bit_string(&self) -> bool {
        self.outer.as_ref().is_some_and(|o| o.tag == Tag::BIT_STRING)
    }
}

fn swallowed<'a>(consumed: usize) -> Option<Step<'a>> {
    (consumed > 0).then_some(Step { consumed, kind: StepKind::Skipped })
}

impl<S: EventSource> EventSource for StringReassembler<S> {
    fn step<'a>(&mut self, input: &'a [u8], eof: bool) -> Result<Step<'a>, Error> {
        loop {
            let step = self.inner.step(input, eof)?;
            let consumed = step.consumed;
            let StepKind::Event(event) = step.kind else {
                return Ok(step);
            };
            let swallow = match event {
                Event::Header { header, depth } => match self.outer.clone() {
                    None if header.tag().class == Class::Universal
                        && is_string_type(header.tag()) =>
                    {
                        self.last_unused = None;
                        self.outer = Some(Outer { tag: header.tag(), depth });
                        if header.tag() == Tag::BIT_STRING {
                            self.bits = BitSegments::default();
                            if !header.constructed() {
                                self.bits.open(depth);
                            }
                        }
                        let header = header.into_primitive();
                        return Ok(Step {
                            consumed,
                            kind: StepKind::Event(Event::Header { header, depth }),
                        });
                    }
                    None => {
                        return Ok(Step {
                            consumed,
                            kind: StepKind::Event(Event::Header { header, depth }),
                        });
                    }
                    Some(outer) => {
                        if header.tag() != outer.tag {
                            let kind = ErrorKind::UnexpectedTag {
                                expected: Some(outer.tag),
                                found: header.tag(),
                            };
                            return Err(Error::new(kind, header.offset()));
                        }
                        if self.is_bit_string() {
                            if self.bits.previous_unused != 0 {
                                let e = ValueError::BitStringUnusedBits;
                                return Err(Error::value(e, header.offset()));
                            }
                            if !header.constructed() {
                                self.bits.open(depth);
                            }
                        }
                        true
                    }
                },
                Event::Content(chunk) => {
                    if self.is_bit_string() {
                        let base = self
                            .inner
                            .position()
                            .saturating_sub(crate::util::saturating_to_u64(chunk.len()));
                        let data = self.bits.strip(chunk).map_err(|e| Error::value(e, base))?;
                        if data.is_empty() {
                            true
                        } else {
                            return Ok(Step {
                                consumed,
                                kind: StepKind::Event(Event::Content(data)),
                            });
                        }
                    } else {
                        return Ok(Step { consumed, kind: StepKind::Event(Event::Content(chunk)) });
                    }
                }
                Event::End { tag, start, end, depth } => {
                    let rules = self.inner.rules();
                    let is_outer = self.outer.as_ref().is_some_and(|o| o.depth == depth);
                    if self.is_bit_string() && self.bits.open_depth == Some(depth) {
                        let closing = self.bits.close(rules);
                        closing.map_err(|e| Error::value(e, start))?;
                    }
                    if is_outer {
                        if self.is_bit_string() {
                            self.last_unused = Some(self.bits.previous_unused);
                        }
                        self.outer = None;
                        return Ok(Step {
                            consumed,
                            kind: StepKind::Event(Event::End { tag, start, end, depth }),
                        });
                    }
                    if self.outer.is_none() {
                        return Ok(Step {
                            consumed,
                            kind: StepKind::Event(Event::End { tag, start, end, depth }),
                        });
                    }
                    true
                }
            };
            if swallow && let Some(step) = swallowed(consumed) {
                return Ok(step);
            }
        }
    }

    fn gather_content(&mut self) -> Result<(), Error> {
        self.inner.gather_content()
    }

    fn skip_content(&mut self) -> Result<(), Error> {
        self.inner.skip_content()
    }

    fn tighten_rules(&mut self, rules: Rules) -> Result<(), Error> {
        self.inner.tighten_rules(rules)
    }

    fn position(&self) -> u64 {
        self.inner.position()
    }

    fn depth(&self) -> usize {
        self.inner.depth()
    }

    fn deviations(&self) -> &Deviations {
        self.inner.deviations()
    }

    fn rules(&self) -> Rules {
        self.inner.rules()
    }
}
