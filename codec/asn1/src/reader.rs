//! The complete-buffer reader.

use crate::util::{head, saturating_to_u64, tail};
use crate::{
    Any, Config, Decode, Deviations, Error, ErrorKind, Event, EventSource, Header, HeaderParse,
    Length, MatchTag, Rules, StepKind, Tag, Tokenizer, Tolerance, Tolerances, Unknown, ValueCount,
};

/// The deepest nesting a reader accepts.
pub(crate) const MAX_DEPTH: usize = 32;

/// Zero-copy typed decoding over a contiguous slice that holds each TLV whole.
///
/// The input is usually one TLV, such as a certificate, but may be several back to back: each
/// [`read`](SliceReader::read) takes one, [`finish`](SliceReader::finish) fails with
/// [`ErrorKind::TrailingData`] if any remain, and a TLV cut short is
/// [`ErrorKind::Truncated`]. The reader that [`read_sequence`](SliceReader::read_sequence) and
/// [`read_set`](SliceReader::read_set) pass to their closure works the same way over the
/// contents. Nesting is limited to 32 levels.
#[derive(Clone, Debug)]
pub struct SliceReader<'a> {
    rest: &'a [u8],
    offset: u64,
    config: Config,
    rules: Rules,
    deviations: Deviations,
    limit: Option<u64>,
    short: bool,
    depth: usize,
    field_tolerances: Tolerances,
}

struct Tlv<'a> {
    header: Header<'a>,
    contents: &'a [u8],
    raw: &'a [u8],
    short: bool,
}

impl<'a> SliceReader<'a> {
    /// A reader over `input`, whose first byte is at offset 0.
    pub fn new(input: &'a [u8], config: &Config) -> Self {
        Self::with_base(input, 0, config)
    }

    /// A reader over `input`, whose first byte is at absolute offset `base`.
    pub fn with_base(input: &'a [u8], base: u64, config: &Config) -> Self {
        SliceReader {
            rest: input,
            offset: base,
            config: config.clone(),
            rules: config.rules(),
            deviations: Deviations::default(),
            limit: None,
            short: false,
            depth: 0,
            field_tolerances: Tolerances::NONE,
        }
    }

    /// The tag of the next value, or `None` at the end of the input.
    ///
    /// # Errors
    ///
    /// Header errors of the next value, and [`ErrorKind::Truncated`] if the enclosing value
    /// declared more bytes than the input holds.
    pub fn peek_tag(&self) -> Result<Option<Tag>, Error> {
        if self.rest.is_empty() {
            return if self.short { Err(self.truncated()) } else { Ok(None) };
        }
        self.header().map(|h| Some(h.tag()))
    }

    /// Reads one value of type `T`.
    ///
    /// # Errors
    ///
    /// Whatever `T`'s decoder reports; [`ErrorKind::Truncated`] when the input is empty.
    pub fn read<T: Decode<'a>>(&mut self) -> Result<T, Error> {
        T::decode(self)
    }

    /// Reads one value of type `T` if the next tag is one `T` accepts, otherwise reads
    /// nothing.
    ///
    /// # Errors
    ///
    /// As [`read`](SliceReader::read) and [`peek_tag`](SliceReader::peek_tag).
    pub fn read_optional<T: Decode<'a> + MatchTag>(&mut self) -> Result<Option<T>, Error> {
        match self.peek_tag()? {
            Some(tag) if T::matches_tag(tag) => self.read().map(Some),
            _ => Ok(None),
        }
    }

    /// Reads one SEQUENCE and runs `f` on a reader over its contents, which `f` must consume
    /// entirely ([`ErrorKind::TrailingData`] otherwise). Indefinite lengths work.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnexpectedTag`] if the next value isn't a SEQUENCE, plus `f`'s errors.
    pub fn read_sequence<R>(
        &mut self,
        f: impl FnOnce(&mut SliceReader<'a>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.read_tlv_with(Some(Tag::SEQUENCE), |_, contents| f(contents))
    }

    /// Reads one SET and runs `f` on a reader over its contents, which `f` must consume
    /// entirely.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnexpectedTag`] if the next value isn't a SET, plus `f`'s errors.
    pub fn read_set<R>(
        &mut self,
        f: impl FnOnce(&mut SliceReader<'a>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.read_tlv_with(Some(Tag::SET), |_, contents| f(contents))
    }

    /// Reads one value of any tag, checks its tag against `expected` if given, and runs `f`
    /// on its header and a reader over its contents, which `f` must consume entirely.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnexpectedTag`], [`ErrorKind::TrailingData`] and `f`'s errors.
    pub fn read_tlv_with<R>(
        &mut self,
        expected: Option<Tag>,
        f: impl FnOnce(&Header<'a>, &mut SliceReader<'a>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let tlv = self.take_tlv()?;
        let found = tlv.header.tag();
        if let Some(tag) = expected
            && tag != found
        {
            return Err(Error::new(
                ErrorKind::UnexpectedTag { expected: Some(tag), found },
                tlv.header.offset(),
            ));
        }
        let mut contents = self.contents_reader(&tlv);
        let result = f(&tlv.header, &mut contents)?;
        contents.finish_contents()?;
        self.deviations.merge(&contents.deviations);
        Ok(result)
    }

    /// Runs `f` with stricter `rules` in force, like the tokenizer's `tighten_rules` for one
    /// subtree.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::RulesLoosened`] if `rules` is looser than the current ones, plus `f`'s
    /// errors.
    pub fn tighten_rules<R>(
        &mut self,
        rules: Rules,
        f: impl FnOnce(&mut SliceReader<'a>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        if rules < self.rules {
            return Err(Error::new(ErrorKind::RulesLoosened, self.offset));
        }
        let previous = core::mem::replace(&mut self.rules, rules);
        let result = f(self);
        self.rules = previous;
        result
    }

    /// Runs `f` and returns the exact bytes it consumed together with its result. This
    /// captures signed bytes, such as a TBS structure.
    ///
    /// # Errors
    ///
    /// `f`'s errors.
    pub fn read_with_raw<R>(
        &mut self,
        f: impl FnOnce(&mut SliceReader<'a>) -> Result<R, Error>,
    ) -> Result<(&'a [u8], R), Error> {
        let before = self.rest;
        let result = f(self)?;
        let consumed = before.len() - self.rest.len();
        Ok((head(before, consumed), result))
    }

    /// Runs `f` with `tolerance` enabled for the next reads, if the configuration allows it.
    pub fn with_tolerance<R>(
        &mut self,
        tolerance: Tolerance,
        f: impl FnOnce(&mut SliceReader<'a>) -> R,
    ) -> R {
        let previous = self.field_tolerances.clone();
        self.field_tolerances = previous.clone().with(tolerance);
        let result = f(self);
        self.field_tolerances = previous;
        result
    }

    /// Whether `tolerance` is both allowed by the configuration and enabled for the current
    /// field.
    pub fn tolerates(&self, tolerance: Tolerance) -> bool {
        self.config.tolerances().contains(tolerance) && self.field_tolerances.contains(tolerance)
    }

    /// Records that a decode used `tolerance`.
    pub fn record_deviation(&mut self, tolerance: Tolerance) {
        self.deviations.record(tolerance);
    }

    /// The tolerances used so far.
    pub fn deviations(&self) -> &Deviations {
        &self.deviations
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The rules currently in force.
    pub fn rules(&self) -> Rules {
        self.rules
    }

    /// The absolute offset of the next unread byte.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether the input is exhausted.
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty() && !self.short
    }

    /// Ends reading.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::TrailingData`] if anything is left.
    pub fn finish(self) -> Result<(), Error> {
        self.finish_contents()
    }

    /// Reads the remaining components as an [`Unknown`] after checking that they are
    /// well-formed.
    ///
    /// # Errors
    ///
    /// Any structural error in the remaining bytes.
    pub fn read_unknown(&mut self) -> Result<Unknown<'a>, Error> {
        let snapshot = self.clone();
        self.walk(|_| Ok(()))?;
        self.consume_all();
        Ok(Unknown::new(snapshot))
    }

    /// Skips the remaining components after checking that they are well-formed.
    ///
    /// # Errors
    ///
    /// Any structural error in the remaining bytes.
    pub fn skip_remaining(&mut self) -> Result<(), Error> {
        self.read_unknown().map(drop)
    }

    pub(crate) fn read_any(&mut self) -> Result<Any<'a>, Error> {
        let tlv = self.take_tlv()?;
        if tlv.short {
            return Err(Error::new(ErrorKind::Truncated, self.offset));
        }
        Ok(Any::new(tlv.header, tlv.raw))
    }

    /// Reads everything left as raw bytes; for the contents of a primitive value.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Truncated`] if the enclosing value declared more bytes than the input holds.
    pub fn read_contents(&mut self) -> Result<&'a [u8], Error> {
        if self.short {
            return Err(Error::new(
                ErrorKind::Truncated,
                self.offset.saturating_add(saturating_to_u64(self.rest.len())),
            ));
        }
        let rest = self.rest;
        self.consume_all();
        Ok(rest)
    }

    pub(crate) fn copy_segments(
        &mut self,
        tag: Tag,
        max: usize,
        out: &mut [u8; 32],
    ) -> Result<usize, Error> {
        let mut len = 0;
        self.walk(|event| {
            match event {
                Event::Header { header, .. } if header.tag() != tag => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedTag { expected: Some(tag), found: header.tag() },
                        header.offset(),
                    ));
                }
                Event::Content(chunk) => {
                    let end = len + chunk.len();
                    let dst = if end <= max { out.get_mut(len..end) } else { None };
                    let Some(dst) = dst else {
                        return Err(Error::value(crate::ValueError::InvalidLength, 0));
                    };
                    dst.copy_from_slice(chunk);
                    len = end;
                }
                _ => {}
            }
            Ok(())
        })?;
        self.consume_all();
        Ok(len)
    }

    fn consume_all(&mut self) {
        self.offset = self.offset.saturating_add(saturating_to_u64(self.rest.len()));
        self.rest = &[];
    }

    fn truncated(&self) -> Error {
        Error::new(
            ErrorKind::Truncated,
            self.offset.saturating_add(saturating_to_u64(self.rest.len())),
        )
    }

    fn finish_contents(&self) -> Result<(), Error> {
        if !self.rest.is_empty() {
            return Err(Error::new(ErrorKind::TrailingData, self.offset));
        }
        if self.short {
            return Err(self.truncated());
        }
        Ok(())
    }

    fn tokenizer(&self, base: u64) -> Tokenizer<MAX_DEPTH> {
        let config = self.config.clone().with_value_count(ValueCount::Many);
        let mut tokenizer =
            Tokenizer::starting_at(config, base, MAX_DEPTH.saturating_sub(self.depth), self.limit);
        tokenizer.set_rules(self.rules);
        tokenizer
    }

    /// Runs a tokenizer over everything left, calling `f` on every event.
    fn walk(&self, mut f: impl FnMut(&Event<'a>) -> Result<(), Error>) -> Result<(), Error> {
        let mut tokenizer = self.tokenizer(self.offset);
        let mut used = 0;
        loop {
            let step = tokenizer.step(tail(self.rest, used), true)?;
            used += step.consumed;
            match step.kind {
                StepKind::Event(event) => f(&event)?,
                StepKind::Done => break,
                StepKind::NeedMore { .. } => return Err(self.truncated()),
                StepKind::Skipped => {}
            }
        }
        if self.short {
            return Err(self.truncated());
        }
        Ok(())
    }

    fn header(&self) -> Result<Header<'a>, Error> {
        match Header::decode(self.rest, self.offset, &self.config, self.rules)? {
            HeaderParse::Complete(header) => {
                if header.tag() == Tag::EOC {
                    return Err(Error::new(ErrorKind::UnexpectedEoc, header.offset()));
                }
                Ok(header)
            }
            HeaderParse::Incomplete { at_least } => {
                let room = self.limit.map(|l| l.saturating_sub(self.offset));
                if room.is_some_and(|r| saturating_to_u64(at_least) > r) {
                    Err(Error::new(ErrorKind::ChildOverrunsParent, self.offset))
                } else {
                    Err(self.truncated())
                }
            }
        }
    }

    fn scan_indefinite(&self, header: &Header<'a>) -> Result<usize, Error> {
        let config = self.config.clone().with_value_count(ValueCount::One);
        let mut tokenizer = Tokenizer::<MAX_DEPTH>::starting_at(
            config,
            header.offset(),
            MAX_DEPTH.saturating_sub(self.depth),
            self.limit,
        );
        tokenizer.set_rules(self.rules);
        let mut used = 0;
        loop {
            let step = tokenizer.step(tail(self.rest, used), true)?;
            used += step.consumed;
            match step.kind {
                StepKind::Event(Event::End { depth: 0, .. }) => return Ok(used),
                StepKind::Done | StepKind::NeedMore { .. } => return Err(self.truncated()),
                _ => {}
            }
        }
    }

    fn take_tlv(&mut self) -> Result<Tlv<'a>, Error> {
        if self.rest.is_empty() {
            return Err(self.truncated());
        }
        let header = self.header()?;
        if self.depth >= MAX_DEPTH {
            return Err(Error::new(ErrorKind::DepthExceeded, header.offset()));
        }
        let header_len = header.raw().len();
        let (total, content_len, short) = match header.length() {
            Length::Definite(len) => {
                let end = header
                    .content_offset()
                    .checked_add(len)
                    .ok_or(Error::new(ErrorKind::LengthOverflow, header.offset()))?;
                if self.limit.is_some_and(|l| end > l) {
                    return Err(Error::new(ErrorKind::ChildOverrunsParent, header.offset()));
                }
                let available = self.rest.len() - header_len;
                match usize::try_from(len) {
                    Ok(n) if n <= available => (header_len + n, n, false),
                    _ if header.constructed() => (self.rest.len(), available, true),
                    _ => return Err(self.truncated()),
                }
            }
            Length::Indefinite => {
                let total = self.scan_indefinite(&header)?;
                (total, total.saturating_sub(header_len + 2), false)
            }
        };
        let raw = head(self.rest, total);
        let contents = tail(raw, header_len);
        let contents = head(contents, content_len);
        self.rest = tail(self.rest, total);
        self.offset = self.offset.saturating_add(saturating_to_u64(total));
        Ok(Tlv { header, contents, raw, short })
    }

    fn contents_reader(&self, tlv: &Tlv<'a>) -> SliceReader<'a> {
        let limit = match tlv.header.length() {
            Length::Definite(len) => tlv.header.content_offset().checked_add(len),
            Length::Indefinite => self.limit,
        };
        SliceReader {
            rest: tlv.contents,
            offset: tlv.header.content_offset(),
            config: self.config.clone(),
            rules: self.rules,
            deviations: Deviations::default(),
            limit,
            short: tlv.short,
            depth: self.depth + 1,
            field_tolerances: self.field_tolerances.clone(),
        }
    }
}
