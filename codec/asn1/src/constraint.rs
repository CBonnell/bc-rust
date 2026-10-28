//! Subtype constraints, evaluated at compile time into interval sets.

use core::cmp::Ordering;

/// Types a `SIZE` constraint applies to.
pub trait SizeConstrainable {
    /// Octets for OCTET STRING, bits for BIT STRING, characters (not bytes) for character
    /// strings, elements for SEQUENCE OF and SET OF.
    fn constraint_size(&self) -> u64;
}

/// Types a value-range constraint applies to.
pub trait RangeConstrainable {
    /// Compares the value with `bound`, without converting the value to a fixed width.
    fn cmp_bound(&self, bound: i128) -> Ordering;
}

/// Types a `FROM` constraint applies to.
pub trait AlphabetConstrainable {
    /// The characters of the value.
    fn constraint_chars(&self) -> impl Iterator<Item = char>;
}

/// The most disjoint intervals a constraint can normalize to.
pub const MAX_INTERVALS: usize = 32;

/// A sorted list of disjoint closed intervals of `i128`, built by `const fn` constructors so
/// that constraint expressions are normalized at compile time.
///
/// A constraint more complex than [`MAX_INTERVALS`] intervals fails const evaluation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IntervalSet {
    ranges: [(i128, i128); MAX_INTERVALS],
    len: usize,
}

#[allow(clippy::indexing_slicing, clippy::panic)]
impl IntervalSet {
    /// The empty set.
    pub const EMPTY: IntervalSet = IntervalSet { ranges: [(0, 0); MAX_INTERVALS], len: 0 };

    /// Every value.
    pub const ALL: IntervalSet = IntervalSet::range(i128::MIN, i128::MAX);

    /// The set holding only `v`.
    pub const fn single(v: i128) -> Self {
        Self::range(v, v)
    }

    /// The closed interval from `lo` to `hi`; empty if `lo > hi`.
    pub const fn range(lo: i128, hi: i128) -> Self {
        let mut set = Self::EMPTY;
        if lo <= hi {
            set.ranges[0] = (lo, hi);
            set.len = 1;
        }
        set
    }

    const fn push(&mut self, lo: i128, hi: i128) {
        if self.len == MAX_INTERVALS {
            panic!("constraint is too complex: too many disjoint intervals");
        }
        self.ranges[self.len] = (lo, hi);
        self.len += 1;
    }

    /// The values in either set.
    pub const fn union(&self, other: &Self) -> Self {
        let mut out = Self::EMPTY;
        let (mut a, mut b) = (0, 0);
        let mut pending: Option<(i128, i128)> = None;
        while a < self.len || b < other.len {
            let next = if b >= other.len || (a < self.len && self.ranges[a].0 <= other.ranges[b].0)
            {
                a += 1;
                self.ranges[a - 1]
            } else {
                b += 1;
                other.ranges[b - 1]
            };
            pending = match pending {
                Some((lo, hi)) if hi == i128::MAX || next.0 <= hi + 1 => {
                    Some((lo, if next.1 > hi { next.1 } else { hi }))
                }
                Some((lo, hi)) => {
                    out.push(lo, hi);
                    Some(next)
                }
                None => Some(next),
            };
        }
        if let Some((lo, hi)) = pending {
            out.push(lo, hi);
        }
        out
    }

    /// The values in both sets.
    pub const fn intersection(&self, other: &Self) -> Self {
        let mut out = Self::EMPTY;
        let (mut a, mut b) = (0, 0);
        while a < self.len && b < other.len {
            let lo = if self.ranges[a].0 > other.ranges[b].0 {
                self.ranges[a].0
            } else {
                other.ranges[b].0
            };
            let hi = if self.ranges[a].1 < other.ranges[b].1 {
                self.ranges[a].1
            } else {
                other.ranges[b].1
            };
            if lo <= hi {
                out.push(lo, hi);
            }
            if self.ranges[a].1 < other.ranges[b].1 {
                a += 1;
            } else {
                b += 1;
            }
        }
        out
    }

    /// The values in this set but not in `other`.
    pub const fn except(&self, other: &Self) -> Self {
        let mut out = Self::EMPTY;
        let mut a = 0;
        while a < self.len {
            let (lo, hi) = self.ranges[a];
            let mut cursor = lo;
            let mut exhausted = false;
            let mut b = 0;
            while b < other.len && !exhausted {
                let (b_lo, b_hi) = other.ranges[b];
                if b_hi >= cursor && b_lo <= hi {
                    if b_lo > cursor {
                        out.push(cursor, b_lo - 1);
                    }
                    if b_hi >= hi {
                        exhausted = true;
                    } else {
                        cursor = b_hi + 1;
                    }
                }
                b += 1;
            }
            if !exhausted {
                out.push(cursor, hi);
            }
            a += 1;
        }
        out
    }

    /// `lo..hi` with the endpoints excluded: `lo <.. <hi`.
    pub const fn open_range(lo: i128, hi: i128) -> Self {
        if lo == i128::MAX || hi == i128::MIN {
            return Self::EMPTY;
        }
        Self::range(lo + 1, hi - 1)
    }

    /// Whether `v` is in the set.
    pub const fn contains(&self, v: i128) -> bool {
        let (mut lo, mut hi) = (0, self.len);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (r_lo, r_hi) = self.ranges[mid];
            if v < r_lo {
                hi = mid;
            } else if v > r_hi {
                lo = mid + 1;
            } else {
                return true;
            }
        }
        false
    }

    /// Whether a value that compares with `cmp` is in the set; one binary search, without
    /// converting the value to a fixed width.
    pub fn contains_by(&self, cmp: impl Fn(i128) -> Ordering) -> bool {
        let ranges = self.ranges.get(..self.len).unwrap_or(&[]);
        ranges
            .binary_search_by(|&(lo, hi)| {
                if cmp(lo) == Ordering::Less {
                    Ordering::Greater
                } else if cmp(hi) == Ordering::Greater {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .is_ok()
    }
}

/// Whether `value`'s size is in `set`.
pub fn check_size<T: SizeConstrainable + ?Sized>(set: &IntervalSet, value: &T) -> bool {
    let size = value.constraint_size();
    set.contains_by(|bound| i128::from(size).cmp(&bound))
}

/// Whether `value` is in `set`.
pub fn check_range<T: RangeConstrainable + ?Sized>(set: &IntervalSet, value: &T) -> bool {
    set.contains_by(|bound| value.cmp_bound(bound))
}

/// Whether every character of `value` is in `set`.
pub fn check_alphabet<T: AlphabetConstrainable + ?Sized>(set: &IntervalSet, value: &T) -> bool {
    value.constraint_chars().all(|c| set.contains(i128::from(u32::from(c))))
}

macro_rules! range_constrainable {
    ($($t:ty),*) => {$(
        impl RangeConstrainable for $t {
            fn cmp_bound(&self, bound: i128) -> Ordering {
                i128::try_from(*self).map_or(Ordering::Greater, |v| v.cmp(&bound))
            }
        }
    )*};
}
range_constrainable!(i8, i16, i32, i64, i128, u8, u16, u32, u64, u128);

impl RangeConstrainable for crate::Int<'_> {
    fn cmp_bound(&self, bound: i128) -> Ordering {
        match i128::try_from(self) {
            Ok(v) => v.cmp(&bound),
            Err(_) if self.is_negative() => Ordering::Less,
            Err(_) => Ordering::Greater,
        }
    }
}

impl RangeConstrainable for crate::Enumerated<'_> {
    fn cmp_bound(&self, bound: i128) -> Ordering {
        self.as_int().cmp_bound(bound)
    }
}

impl SizeConstrainable for crate::BitString<'_> {
    fn constraint_size(&self) -> u64 {
        crate::util::saturating_to_u64(self.len_bits())
    }
}

impl SizeConstrainable for crate::NamedBits<'_> {
    fn constraint_size(&self) -> u64 {
        self.as_bit_string().constraint_size()
    }
}
