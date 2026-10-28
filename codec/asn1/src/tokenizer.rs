//! The sans-io tokenizer.

use crate::util::saturating_to_u64;
use crate::{
    Config, Deviations, Error, ErrorKind, Header, HeaderParse, Length, Rules, Tag, ValueCount,
};

/// The outcome of one [`EventSource::step`] call.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step<'a> {
    /// Bytes of `input` the caller must now discard.
    pub consumed: usize,
    /// What happened.
    pub kind: StepKind<'a>,
}

/// What a [`Step`] produced.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StepKind<'a> {
    /// An event.
    Event(Event<'a>),
    /// Bytes consumed while skipping; no event.
    Skipped,
    /// The input must hold at least this many bytes (counted from `position()`) to make
    /// progress. This is a lower bound, not a total size.
    NeedMore {
        /// The minimum input length.
        at_least: usize,
    },
    /// Every value in the input is complete.
    Done,
}

/// One event of the balanced event stream. Every encoding is a tree of TLVs, so these three
/// are all there is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event<'a> {
    /// A value starts.
    Header {
        /// The value's header.
        header: Header<'a>,
        /// The number of open ancestors; outermost values have depth 0.
        depth: usize,
    },
    /// A chunk of a primitive value's contents.
    Content(&'a [u8]),
    /// A value ends.
    End {
        /// The value's tag.
        tag: Tag,
        /// Absolute offset of the value's first byte.
        start: u64,
        /// Absolute offset just past the value.
        end: u64,
        /// The number of open ancestors.
        depth: usize,
    },
}

/// A source of [`Event`]s: the tokenizer, or a filter wrapping another source.
pub trait EventSource {
    /// Advances by one step.
    ///
    /// `input` starts at [`position()`](EventSource::position). `eof` means `input` holds every
    /// remaining byte, so truncation becomes [`ErrorKind::Truncated`] instead of an endless
    /// `NeedMore`. The caller discards `consumed` bytes afterwards.
    fn step<'a>(&mut self, input: &'a [u8], eof: bool) -> Result<Step<'a>, Error>;

    /// After a primitive `Header`: the following steps return `NeedMore` until all remaining
    /// content is in `input`, then exactly one `Content` with all of it, then `End`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidState`] unless the last event was a primitive `Header`.
    fn gather_content(&mut self) -> Result<(), Error>;

    /// After a `Header`: the following steps return `Skipped` or `NeedMore` until the value
    /// ends, then that value's `End`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidState`] unless the last event was a `Header`.
    fn skip_content(&mut self) -> Result<(), Error>;

    /// After a `Header`: applies stricter rules to that value's subtree, reverting at its
    /// `End`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::RulesLoosened`] if `rules` is looser than the current ones, and
    /// [`ErrorKind::InvalidState`] unless the last event was a `Header`.
    fn tighten_rules(&mut self, rules: Rules) -> Result<(), Error>;

    /// The absolute position of the next unconsumed byte.
    fn position(&self) -> u64;

    /// The number of values currently open.
    fn depth(&self) -> usize;

    /// The tolerances used so far.
    fn deviations(&self) -> &Deviations;

    /// The rules in force for the innermost open value, or the configured rules at top level.
    fn rules(&self) -> Rules;
}

#[derive(Clone, Copy, Debug)]
struct Frame {
    tag: Tag,
    start: u64,
    rules: Rules,
    end: Option<u64>,
    constructed: bool,
}

impl Frame {
    const EMPTY: Frame =
        Frame { tag: Tag::EOC, start: 0, rules: Rules::Der, end: Some(0), constructed: false };
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Normal,
    Gather,
    Skip { nesting: usize, pending: u64 },
}

enum Next<'a> {
    Header(Header<'a>),
    Wait(StepKind<'a>),
}

/// The sans-io pull tokenizer.
///
/// `DEPTH` is the number of values that may be open at once. It sizes the tokenizer's stack.
/// A level can cost an attacker as little as two bytes (a BER indefinite-length header, with
/// the closing octets never sent), so raising it exposes deeper nesting costs; X.509 needs
/// about 10.
///
/// After an error every further call returns the same error.
#[derive(Clone, Debug)]
pub struct Tokenizer<const DEPTH: usize = 32> {
    config: Config,
    stack: [Frame; DEPTH],
    len: usize,
    position: u64,
    completed: bool,
    mode: Mode,
    just_header: bool,
    failed: Option<Error>,
    deviations: Deviations,
    limit: Option<u64>,
    depth_limit: usize,
}

impl<const DEPTH: usize> Tokenizer<DEPTH> {
    /// Creates a tokenizer positioned at offset 0.
    pub fn new(config: Config) -> Self {
        Self::starting_at(config, 0, DEPTH, None)
    }

    pub(crate) fn starting_at(
        config: Config,
        position: u64,
        depth_limit: usize,
        limit: Option<u64>,
    ) -> Self {
        Tokenizer {
            config,
            stack: [Frame::EMPTY; DEPTH],
            len: 0,
            position,
            completed: false,
            mode: Mode::Normal,
            just_header: false,
            failed: None,
            deviations: Deviations::default(),
            limit,
            depth_limit: depth_limit.min(DEPTH),
        }
    }

    pub(crate) fn set_rules(&mut self, rules: Rules) {
        self.config = self.config.clone().with_rules(rules);
    }

    fn top(&self) -> Option<&Frame> {
        self.len.checked_sub(1).and_then(|i| self.stack.get(i))
    }

    fn top_mut(&mut self) -> Option<&mut Frame> {
        self.len.checked_sub(1).and_then(|i| self.stack.get_mut(i))
    }

    fn active_rules(&self) -> Rules {
        self.top().map_or(self.config.rules(), |f| f.rules)
    }

    fn limit_end(&self) -> Option<u64> {
        let frames = self.stack.get(..self.len).unwrap_or(&[]);
        frames.iter().rev().find_map(|f| f.end).or(self.limit)
    }

    fn pop_end(&mut self, consumed: usize) -> Step<'static> {
        self.position = self.position.saturating_add(saturating_to_u64(consumed));
        let frame = self.top().copied().unwrap_or(Frame::EMPTY);
        self.len = self.len.saturating_sub(1);
        self.mode = Mode::Normal;
        if self.len == 0 {
            self.completed = true;
        }
        Step {
            consumed,
            kind: StepKind::Event(Event::End {
                tag: frame.tag,
                start: frame.start,
                end: frame.end.unwrap_or(self.position),
                depth: self.len,
            }),
        }
    }

    fn next_header<'a>(&self, input: &'a [u8], eof: bool) -> Result<Next<'a>, Error> {
        let remaining_in_limit = self.limit_end().map(|l| l.saturating_sub(self.position));
        let avail = match remaining_in_limit {
            Some(r) => input.len().min(usize::try_from(r).unwrap_or(usize::MAX)),
            None => input.len(),
        };
        let window = input.get(..avail).unwrap_or(input);
        match Header::decode(window, self.position, &self.config, self.active_rules())? {
            HeaderParse::Complete(h) => Ok(Next::Header(h)),
            HeaderParse::Incomplete { at_least } => {
                if remaining_in_limit.is_some_and(|r| saturating_to_u64(at_least) > r) {
                    return Err(Error::new(ErrorKind::ChildOverrunsParent, self.position));
                }
                if eof {
                    return Err(Error::new(
                        ErrorKind::Truncated,
                        self.position.saturating_add(saturating_to_u64(input.len())),
                    ));
                }
                Ok(Next::Wait(StepKind::NeedMore { at_least }))
            }
        }
    }

    fn check_depth(&self, extra: usize, at: u64) -> Result<(), Error> {
        if self.len + extra >= self.depth_limit {
            return Err(Error::new(ErrorKind::DepthExceeded, at));
        }
        Ok(())
    }

    fn definite_end(&self, header: &Header<'_>, len: u64) -> Result<u64, Error> {
        let end = header
            .content_offset()
            .checked_add(len)
            .ok_or(Error::new(ErrorKind::LengthOverflow, header.offset()))?;
        if self.limit_end().is_some_and(|l| end > l) {
            return Err(Error::new(ErrorKind::ChildOverrunsParent, header.offset()));
        }
        Ok(end)
    }

    /// End-of-contents is exactly the two octets `00 00`; any other encoding of universal tag
    /// 0 is an error.
    fn is_eoc(header: &Header<'_>) -> Result<bool, Error> {
        if header.tag() != Tag::EOC {
            return Ok(false);
        }
        if !matches!(header.raw(), [0, 0]) {
            return Err(Error::new(ErrorKind::UnexpectedEoc, header.offset()));
        }
        Ok(true)
    }

    fn step_primitive<'a>(
        &mut self,
        input: &'a [u8],
        eof: bool,
        remaining: u64,
        all: bool,
    ) -> Result<Step<'a>, Error> {
        let wanted = if all {
            usize::try_from(remaining)
                .map_err(|_| Error::new(ErrorKind::ElementTooLarge, self.position))?
        } else {
            1
        };
        if input.len() < wanted {
            if eof {
                return Err(Error::new(
                    ErrorKind::Truncated,
                    self.position.saturating_add(saturating_to_u64(input.len())),
                ));
            }
            return Ok(Step { consumed: 0, kind: StepKind::NeedMore { at_least: wanted } });
        }
        let n = usize::try_from(remaining).map_or(input.len(), |r| r.min(input.len()));
        let chunk = input.get(..n).unwrap_or(input);
        self.position = self.position.saturating_add(saturating_to_u64(n));
        Ok(Step { consumed: n, kind: StepKind::Event(Event::Content(chunk)) })
    }

    fn step_normal<'a>(&mut self, input: &'a [u8], eof: bool) -> Result<Step<'a>, Error> {
        let Some(&top) = self.top() else {
            return self.step_root(input, eof);
        };
        if !top.constructed {
            let end = top.end.unwrap_or(self.position);
            let remaining = end.saturating_sub(self.position);
            if remaining == 0 {
                return Ok(self.pop_end(0));
            }
            let all = matches!(self.mode, Mode::Gather);
            let step = self.step_primitive(input, eof, remaining, all)?;
            if matches!(step.kind, StepKind::Event(_)) {
                self.mode = Mode::Normal;
            }
            return Ok(step);
        }
        if top.end == Some(self.position) {
            return Ok(self.pop_end(0));
        }
        let header = match self.next_header(input, eof)? {
            Next::Header(h) => h,
            Next::Wait(kind) => return Ok(Step { consumed: 0, kind }),
        };
        if Self::is_eoc(&header)? {
            if top.end.is_some() {
                return Err(Error::new(ErrorKind::UnexpectedEoc, header.offset()));
            }
            return Ok(self.pop_end(header.raw().len()));
        }
        self.open(header)
    }

    fn step_root<'a>(&mut self, input: &'a [u8], eof: bool) -> Result<Step<'a>, Error> {
        let many = self.config.value_count() == ValueCount::Many;
        if input.is_empty() {
            let kind = if !eof {
                StepKind::NeedMore { at_least: 1 }
            } else if self.completed || many {
                StepKind::Done
            } else {
                return Err(Error::new(ErrorKind::Truncated, self.position));
            };
            return Ok(Step { consumed: 0, kind });
        }
        if self.completed && !many {
            return Err(Error::new(ErrorKind::TrailingData, self.position));
        }
        let header = match self.next_header(input, eof)? {
            Next::Header(h) => h,
            Next::Wait(kind) => return Ok(Step { consumed: 0, kind }),
        };
        if Self::is_eoc(&header)? {
            return Err(Error::new(ErrorKind::UnexpectedEoc, header.offset()));
        }
        self.open(header)
    }

    fn open<'a>(&mut self, header: Header<'a>) -> Result<Step<'a>, Error> {
        self.check_depth(0, header.offset())?;
        let end = match header.length() {
            Length::Definite(len) => Some(self.definite_end(&header, len)?),
            Length::Indefinite => None,
        };
        let frame = Frame {
            tag: header.tag(),
            start: header.offset(),
            rules: self.active_rules(),
            end,
            constructed: header.constructed(),
        };
        let depth = self.len;
        if let Some(slot) = self.stack.get_mut(depth) {
            *slot = frame;
        }
        self.len += 1;
        let consumed = header.raw().len();
        self.position = self.position.saturating_add(saturating_to_u64(consumed));
        self.just_header = true;
        Ok(Step { consumed, kind: StepKind::Event(Event::Header { header, depth }) })
    }

    fn step_skip<'a>(
        &mut self,
        input: &'a [u8],
        eof: bool,
        nesting: usize,
        pending: u64,
    ) -> Result<Step<'a>, Error> {
        if pending > 0 {
            if input.is_empty() {
                if eof {
                    return Err(Error::new(ErrorKind::Truncated, self.position));
                }
                return Ok(Step { consumed: 0, kind: StepKind::NeedMore { at_least: 1 } });
            }
            let n = usize::try_from(pending).map_or(input.len(), |p| p.min(input.len()));
            self.position = self.position.saturating_add(saturating_to_u64(n));
            self.mode = Mode::Skip { nesting, pending: pending - saturating_to_u64(n) };
            return Ok(Step { consumed: n, kind: StepKind::Skipped });
        }
        if self.top().is_some_and(|f| f.end.is_some()) {
            self.mode = Mode::Normal;
            return Ok(self.pop_end(0));
        }
        let header = match self.next_header(input, eof)? {
            Next::Header(h) => h,
            Next::Wait(kind) => return Ok(Step { consumed: 0, kind }),
        };
        let consumed = header.raw().len();
        if Self::is_eoc(&header)? {
            if nesting == 0 {
                self.mode = Mode::Normal;
                return Ok(self.pop_end(consumed));
            }
            self.position = self.position.saturating_add(saturating_to_u64(consumed));
            self.mode = Mode::Skip { nesting: nesting - 1, pending: 0 };
            return Ok(Step { consumed, kind: StepKind::Skipped });
        }
        self.check_depth(nesting, header.offset())?;
        let (nesting, pending) = match header.length() {
            Length::Definite(len) => {
                self.definite_end(&header, len)?;
                (nesting, len)
            }
            Length::Indefinite => (nesting + 1, 0),
        };
        self.position = self.position.saturating_add(saturating_to_u64(consumed));
        self.mode = Mode::Skip { nesting, pending };
        Ok(Step { consumed, kind: StepKind::Skipped })
    }

    fn require_header_state(&self) -> Result<(), Error> {
        if self.just_header && self.failed.is_none() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidState, self.position))
        }
    }
}

impl<const DEPTH: usize> EventSource for Tokenizer<DEPTH> {
    fn step<'a>(&mut self, input: &'a [u8], eof: bool) -> Result<Step<'a>, Error> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        self.just_header = false;
        let result = match self.mode {
            Mode::Normal | Mode::Gather => self.step_normal(input, eof),
            Mode::Skip { nesting, pending } => self.step_skip(input, eof, nesting, pending),
        };
        if let Err(e) = &result {
            self.failed = Some(e.clone());
        }
        result
    }

    fn gather_content(&mut self) -> Result<(), Error> {
        self.require_header_state()?;
        if self.top().is_some_and(|f| f.constructed) {
            return Err(Error::new(ErrorKind::InvalidState, self.position));
        }
        self.mode = Mode::Gather;
        Ok(())
    }

    fn skip_content(&mut self) -> Result<(), Error> {
        self.require_header_state()?;
        let position = self.position;
        let pending = self.top().and_then(|f| f.end).map_or(0, |end| end.saturating_sub(position));
        self.mode = Mode::Skip { nesting: 0, pending };
        Ok(())
    }

    fn tighten_rules(&mut self, rules: Rules) -> Result<(), Error> {
        self.require_header_state()?;
        let Some(frame) = self.top_mut() else {
            return Err(Error::new(ErrorKind::InvalidState, 0));
        };
        if rules < frame.rules {
            return Err(Error::new(ErrorKind::RulesLoosened, frame.start));
        }
        frame.rules = rules;
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }

    fn depth(&self) -> usize {
        self.len
    }

    fn deviations(&self) -> &Deviations {
        &self.deviations
    }

    fn rules(&self) -> Rules {
        self.active_rules()
    }
}
