use core::fmt;

use super::{ContentCodec, fixed_tag};
use crate::util::write_slice;
use crate::{Error, Rules, Tag, ValueError, base128};

/// NULL.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct Null;

fixed_tag!(Null, Tag::NULL);

impl<'a> ContentCodec<'a> for Null {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        if content.is_empty() { Ok(Null) } else { Err(ValueError::NullNotEmpty) }
    }

    fn content_len(&self) -> usize {
        0
    }

    fn encode_content(&self, _out: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }
}

/// Checks the component structure shared by OBJECT IDENTIFIER and RELATIVE-OID.
const fn validate_components(mut bytes: &[u8]) -> Result<(), ValueError> {
    if bytes.is_empty() {
        return Err(ValueError::OidEmpty);
    }
    let mut at_start = true;
    let mut value: u128 = 0;
    while let [b, rest @ ..] = bytes {
        if at_start && *b == 0x80 {
            return Err(ValueError::OidNotMinimal);
        }
        if value >> 121 != 0 {
            return Err(ValueError::OidArcTooLarge);
        }
        value = (value << 7) | (*b & 0x7F) as u128;
        at_start = *b & 0x80 == 0;
        if at_start {
            value = 0;
        }
        bytes = rest;
    }
    if at_start { Ok(()) } else { Err(ValueError::OidTruncated) }
}

/// An OBJECT IDENTIFIER, storing the validated encoding so equality and hashing are byte
/// comparisons.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Oid<'a> {
    bytes: &'a [u8],
}

impl<'a> Oid<'a> {
    /// Wraps already-encoded OBJECT IDENTIFIER contents after validating them.
    ///
    /// # Errors
    ///
    /// [`ValueError::OidEmpty`], [`ValueError::OidNotMinimal`], [`ValueError::OidTruncated`]
    /// or [`ValueError::OidArcTooLarge`].
    pub const fn new(bytes: &'a [u8]) -> Result<Self, ValueError> {
        match validate_components(bytes) {
            Ok(()) => Ok(Oid { bytes }),
            Err(e) => Err(e),
        }
    }

    /// Encodes `arcs` into `out` and wraps the result.
    ///
    /// # Errors
    ///
    /// [`ValueError::OidEmpty`] for no arcs, [`ValueError::OidFirstArc`] for fewer than two
    /// arcs, a first arc above 2 or a second arc of 40 or more under first arc 0 or 1, and
    /// [`ErrorKind::InsufficientSize`](crate::ErrorKind::InsufficientSize) if `out` is too small.
    pub fn from_arcs(arcs: &[u128], out: &'a mut [u8]) -> Result<Self, Error> {
        let invalid = |e| Error::value(e, 0);
        let (&first, rest) = arcs.split_first().ok_or(invalid(ValueError::OidEmpty))?;
        let (&second, rest) = rest.split_first().ok_or(invalid(ValueError::OidFirstArc))?;
        if first > 2 || (first < 2 && second >= 40) {
            return Err(invalid(ValueError::OidFirstArc));
        }
        let head = first * 40;
        let head = head.checked_add(second).ok_or(invalid(ValueError::OidArcTooLarge))?;
        let mut used = base128::encode(head, out)?;
        for &arc in rest {
            let tail = out.get_mut(used..).unwrap_or_default();
            used += base128::encode(arc, tail)?;
        }
        let encoded: &'a [u8] = out;
        Ok(Oid { bytes: encoded.get(..used).unwrap_or(&[]) })
    }

    /// The validated contents octets.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The arcs, lazily. The first subidentifier yields two arcs.
    pub fn arcs(&self) -> Arcs<'a> {
        Arcs { rest: self.bytes, pending: None, split_first: true }
    }
}

impl fmt::Display for Oid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_arcs(f, self.arcs())
    }
}

fn write_arcs(f: &mut fmt::Formatter<'_>, arcs: Arcs<'_>) -> fmt::Result {
    for (i, arc) in arcs.enumerate() {
        if i > 0 {
            f.write_str(".")?;
        }
        write!(f, "{arc}")?;
    }
    Ok(())
}

/// The arcs of an [`Oid`] or [`RelOid`].
#[derive(Clone, Debug)]
pub struct Arcs<'a> {
    rest: &'a [u8],
    pending: Option<u128>,
    split_first: bool,
}

impl Iterator for Arcs<'_> {
    type Item = u128;

    fn next(&mut self) -> Option<u128> {
        if let Some(arc) = self.pending.take() {
            return Some(arc);
        }
        let (value, used) = base128::decode::<u128>(self.rest).ok()?;
        self.rest = self.rest.get(used..).unwrap_or(&[]);
        if !core::mem::take(&mut self.split_first) {
            return Some(value);
        }
        let first = (value / 40).min(2);
        self.pending = Some(value - first * 40);
        Some(first)
    }
}

fixed_tag!(Oid<'_>, Tag::OBJECT_IDENTIFIER);

impl<'a> ContentCodec<'a> for Oid<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        Oid::new(content)
    }

    fn content_len(&self) -> usize {
        self.bytes.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.bytes)
    }
}

/// A RELATIVE-OID.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RelOid<'a> {
    bytes: &'a [u8],
}

impl<'a> RelOid<'a> {
    /// Wraps already-encoded RELATIVE-OID contents after validating them.
    ///
    /// # Errors
    ///
    /// [`ValueError::OidEmpty`], [`ValueError::OidNotMinimal`], [`ValueError::OidTruncated`]
    /// or [`ValueError::OidArcTooLarge`].
    pub const fn new(bytes: &'a [u8]) -> Result<Self, ValueError> {
        match validate_components(bytes) {
            Ok(()) => Ok(RelOid { bytes }),
            Err(e) => Err(e),
        }
    }

    /// The validated contents octets.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The arcs, lazily.
    pub fn arcs(&self) -> Arcs<'a> {
        Arcs { rest: self.bytes, pending: None, split_first: false }
    }
}

impl fmt::Display for RelOid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_arcs(f, self.arcs())
    }
}

fixed_tag!(RelOid<'_>, Tag::RELATIVE_OID);

impl<'a> ContentCodec<'a> for RelOid<'a> {
    fn decode_content(content: &'a [u8], _rules: Rules) -> Result<Self, ValueError> {
        RelOid::new(content)
    }

    fn content_len(&self) -> usize {
        self.bytes.len()
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.bytes)
    }
}
