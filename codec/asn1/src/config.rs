//! Rules, limits and tolerances.

/// The encoding rules a value is validated against, ordered by strictness.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum Rules {
    /// Basic Encoding Rules.
    Ber,
    /// Distinguished Encoding Rules.
    #[default]
    Der,
}

/// How many top-level values the input holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ValueCount {
    /// Exactly one value.
    #[default]
    One,
    /// Any number of values back to back.
    Many,
}

/// Decoding rules, limits and tolerances.
///
/// Every limit bounds what hostile input can make the parser, or its caller, do. Raising one
/// should be a deliberate choice for a known schema, never a fix for throughput or for input
/// that "doesn't work".
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    rules: Rules,
    value_count: ValueCount,
    max_value_len: u64,
    max_tag_number: u32,
    tolerances: Tolerances,
}

impl Config {
    /// DER rules, [`ValueCount::One`], 64 MiB maximum value length, maximum tag number 16 383
    /// (two base-128 digits) and no tolerances.
    pub const DER: Config = Config {
        rules: Rules::Der,
        value_count: ValueCount::One,
        max_value_len: 64 << 20,
        max_tag_number: 16_383,
        tolerances: Tolerances::NONE,
    };

    /// [`Config::DER`] with BER rules.
    pub const BER: Config = Config::DER.with_rules(Rules::Ber);

    /// Sets the encoding rules.
    pub const fn with_rules(mut self, rules: Rules) -> Self {
        self.rules = rules;
        self
    }

    /// Sets how many top-level values the input holds.
    pub const fn with_value_count(mut self, count: ValueCount) -> Self {
        self.value_count = count;
        self
    }

    /// Sets the longest value, in content octets, that is accepted.
    ///
    /// A nine-octet header can claim 2^60 bytes. The tokenizer never allocates, but
    /// [`StepKind::NeedMore`](crate::StepKind::NeedMore) passes the claim on, and a caller that
    /// grows its buffer to match runs out of memory. Raise this only for a known schema.
    pub const fn with_max_value_len(mut self, len: u64) -> Self {
        self.max_value_len = len;
        self
    }

    /// Sets the largest tag number that is accepted.
    ///
    /// Huge tag numbers appear in no real schema; accepting them only widens the inputs that
    /// different parsers might interpret differently.
    pub const fn with_max_tag_number(mut self, number: u32) -> Self {
        self.max_tag_number = number;
        self
    }

    /// Sets the tolerances a decode may use.
    pub const fn with_tolerances(mut self, tolerances: Tolerances) -> Self {
        self.tolerances = tolerances;
        self
    }

    /// The encoding rules.
    pub const fn rules(&self) -> Rules {
        self.rules
    }

    /// How many top-level values the input holds.
    pub const fn value_count(&self) -> ValueCount {
        self.value_count
    }

    /// The longest accepted value, in content octets.
    pub const fn max_value_len(&self) -> u64 {
        self.max_value_len
    }

    /// The largest accepted tag number.
    pub const fn max_tag_number(&self) -> u32 {
        self.max_tag_number
    }

    /// The tolerances a decode may use.
    pub const fn tolerances(&self) -> &Tolerances {
        &self.tolerances
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::DER
    }
}

/// Each tolerance relaxes one DER-only rule toward what BER allows.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Tolerance {
    /// Accept an encoded DEFAULT value on fields marked `tolerate(encoded_default)`.
    EncodedDefault,
    /// Accept an unsorted DER SET OF on fields marked `tolerate(unsorted_set_of)`.
    UnsortedSetOf,
}

impl Tolerance {
    const fn bit(self) -> u8 {
        match self {
            Tolerance::EncodedDefault => 1,
            Tolerance::UnsortedSetOf => 2,
        }
    }

    const ALL: [Tolerance; 2] = [Tolerance::EncodedDefault, Tolerance::UnsortedSetOf];
}

/// Tolerances a decode may use; all off by default.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Tolerances {
    bits: u8,
}

impl Tolerances {
    /// No tolerances.
    pub const NONE: Tolerances = Tolerances { bits: 0 };

    /// Returns these tolerances with `tolerance` enabled.
    pub const fn with(mut self, tolerance: Tolerance) -> Self {
        self.bits |= tolerance.bit();
        self
    }

    /// Returns these tolerances with `tolerance` disabled.
    pub const fn without(mut self, tolerance: Tolerance) -> Self {
        self.bits &= !tolerance.bit();
        self
    }

    /// Whether `tolerance` is enabled.
    pub const fn contains(&self, tolerance: Tolerance) -> bool {
        self.bits & tolerance.bit() != 0
    }
}

/// Tolerances a decode actually used; only the library constructs it.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Deviations {
    bits: u8,
}

impl Deviations {
    /// Whether `tolerance` was used.
    pub const fn contains(&self, tolerance: Tolerance) -> bool {
        self.bits & tolerance.bit() != 0
    }

    /// Whether no tolerance was used, meaning the input was valid under the strict rules.
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// The tolerances that were used.
    pub fn iter(&self) -> impl Iterator<Item = Tolerance> {
        let bits = self.bits;
        Tolerance::ALL.into_iter().filter(move |t| bits & t.bit() != 0)
    }

    pub(crate) fn record(&mut self, tolerance: Tolerance) {
        self.bits |= tolerance.bit();
    }

    pub(crate) fn merge(&mut self, other: &Deviations) {
        self.bits |= other.bits;
    }
}
