//! Base-128 (VLQ) numbers, used by high-form tag numbers, OID subidentifiers and RELATIVE-OID.

use crate::util::insufficient;
use crate::{Error, ErrorKind};

mod sealed {
    pub trait Sealed {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for u128 {}
}

/// An unsigned integer type a base-128 number can be decoded into: `u32`, `u64` and `u128`.
pub trait Base128Int: Copy + sealed::Sealed {
    /// Width of the type in bits.
    const BITS: u32;
    #[doc(hidden)]
    fn from_u128(v: u128) -> Self;
    #[doc(hidden)]
    fn to_u128(self) -> u128;
}

macro_rules! base128_int {
    ($($t:ty),*) => {$(
        impl Base128Int for $t {
            const BITS: u32 = <$t>::BITS;
            fn from_u128(v: u128) -> Self { v as $t }
            fn to_u128(self) -> u128 { u128::from(self) }
        }
    )*};
}
base128_int!(u32, u64, u128);

/// Decodes a base-128 number from the start of `input`.
///
/// Returns the value and the number of bytes used. Minimal encoding is mandatory in BER as
/// well as DER. Offsets in errors are relative to `input`.
///
/// # Errors
///
/// - [`ErrorKind::NonMinimalBase128`] if the first octet is `0x80`.
/// - [`ErrorKind::Base128Overflow`] if the value doesn't fit `T`.
/// - [`ErrorKind::Truncated`] if `input` ends while bit 8 is still set.
pub fn decode<T: Base128Int>(input: &[u8]) -> Result<(T, usize), Error> {
    let mut value: u128 = 0;
    for (i, &b) in input.iter().enumerate() {
        let at = crate::util::saturating_to_u64(i);
        if i == 0 && b == 0x80 {
            return Err(Error::new(ErrorKind::NonMinimalBase128, at));
        }
        if value >> (T::BITS - 7) != 0 {
            return Err(Error::new(ErrorKind::Base128Overflow, at));
        }
        value = (value << 7) | u128::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Ok((T::from_u128(value), i + 1));
        }
    }
    Err(Error::new(ErrorKind::Truncated, crate::util::saturating_to_u64(input.len())))
}

/// Encodes `v` in the fewest base-128 digits and returns the number of bytes written.
///
/// # Errors
///
/// [`ErrorKind::InsufficientSize`] if `out` is too small; nothing is written.
pub fn encode<T: Base128Int>(v: T, out: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(v);
    let v = v.to_u128();
    let dst = out.get_mut(..len).ok_or_else(|| insufficient(len, 0))?;
    for (i, slot) in dst.iter_mut().enumerate() {
        let shift = 7 * (len - 1 - i);
        let continuation = if i + 1 < len { 0x80 } else { 0 };
        *slot = ((v >> shift) & 0x7F) as u8 | continuation;
    }
    Ok(len)
}

/// The number of bytes [`encode`] writes for `v`.
pub fn encoded_len<T: Base128Int>(v: T) -> usize {
    let bits = 128 - v.to_u128().leading_zeros() as usize;
    bits.div_ceil(7).max(1)
}
