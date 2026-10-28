use super::{ContentCodec, fixed_tag};
use crate::util::write_slice;
use crate::{Error, Rules, Tag, ValueError};

/// The number of days in `month` (1–12) of the Gregorian `year`, or 0 for any other month.
pub const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn check_fields(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Result<(), ValueError> {
    let valid = year <= 9999
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59;
    if valid { Ok(()) } else { Err(ValueError::InvalidTime) }
}

fn ber_grammar(rules: Rules) -> bool {
    cfg!(feature = "ber-time") && rules == Rules::Ber
}

struct Cursor<'x> {
    bytes: &'x [u8],
    at: usize,
}

impl<'x> Cursor<'x> {
    fn new(bytes: &'x [u8]) -> Self {
        Cursor { bytes, at: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn peek_digit(&self) -> bool {
        self.peek().is_some_and(|b| b.is_ascii_digit())
    }

    fn take(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.at += 1;
        Some(b)
    }

    fn digits(&mut self, n: usize) -> Result<u32, ValueError> {
        let mut value = 0u32;
        for _ in 0..n {
            let b = self.take().filter(u8::is_ascii_digit).ok_or(ValueError::InvalidTime)?;
            value = value * 10 + u32::from(b - b'0');
        }
        Ok(value)
    }

    fn two(&mut self) -> Result<u8, ValueError> {
        self.digits(2).map(|v| v as u8)
    }

    fn finish(&self) -> Result<(), ValueError> {
        if self.at == self.bytes.len() { Ok(()) } else { Err(ValueError::InvalidTime) }
    }

    #[cfg(feature = "ber-time")]
    fn utc_offset(&mut self, with_minutes: Option<bool>) -> Result<i16, ValueError> {
        let sign = match self.take() {
            Some(b'+') => 1i16,
            Some(b'-') => -1i16,
            _ => return Err(ValueError::InvalidTime),
        };
        let hours = self.two()?;
        let minutes = match with_minutes {
            Some(true) => self.two()?,
            Some(false) => 0,
            None if self.peek_digit() => self.two()?,
            None => 0,
        };
        if hours > 23 || minutes > 59 {
            return Err(ValueError::InvalidTime);
        }
        Ok(sign * (i16::from(hours) * 60 + i16::from(minutes)))
    }
}

struct Render {
    buf: [u8; 32],
    len: usize,
}

impl Render {
    fn new() -> Self {
        Render { buf: [0; 32], len: 0 }
    }

    fn push(&mut self, b: u8) -> Result<(), ValueError> {
        *self.buf.get_mut(self.len).ok_or(ValueError::InvalidTime)? = b;
        self.len += 1;
        Ok(())
    }

    fn digits(&mut self, value: u32, n: u32) -> Result<(), ValueError> {
        for i in (0..n).rev() {
            self.push(b'0' + (value / 10u32.pow(i) % 10) as u8)?;
        }
        Ok(())
    }

    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    fn write_to(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, self.bytes())
    }
}

/// A UTCTime with four-digit years: two-digit years of 50 or more are 19YY, below 50 are
/// 20YY (RFC 5280 §4.1.2.5.1).
///
/// Decoding checks the month, the day against the month's length (using the four-digit year,
/// so `000229` is valid and `970229` is not), hour 0–23, minute 0–59 and second 0–59.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct UtcTime {
    /// The four-digit year, 1950 through 2049.
    pub year: u16,
    /// The month, 1–12.
    pub month: u8,
    /// The day of the month.
    pub day: u8,
    /// The hour, 0–23.
    pub hour: u8,
    /// The minute, 0–59.
    pub minute: u8,
    /// The second, 0–59.
    pub second: u8,
    /// The offset from UTC in minutes, when the BER form carried one.
    #[cfg(feature = "ber-time")]
    pub utc_offset_minutes: Option<i16>,
    /// Whether the time is local with no UTC relation; never set for a UTCTime.
    #[cfg(feature = "ber-time")]
    pub local: bool,
}

impl UtcTime {
    fn parse(content: &[u8], rules: Rules) -> Result<Self, ValueError> {
        let mut cur = Cursor::new(content);
        let yy = u16::from(cur.two()?);
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        let month = cur.two()?;
        let day = cur.two()?;
        let hour = cur.two()?;
        let minute = cur.two()?;
        let ber = ber_grammar(rules);
        let second = if !ber || cur.peek_digit() { cur.two()? } else { 0 };
        #[cfg(feature = "ber-time")]
        let mut utc_offset_minutes = None;
        match cur.take() {
            Some(b'Z') => {}
            #[cfg(feature = "ber-time")]
            Some(b'+' | b'-') if ber => {
                cur.at -= 1;
                utc_offset_minutes = Some(cur.utc_offset(Some(true))?);
            }
            _ => return Err(ValueError::InvalidTime),
        }
        cur.finish()?;
        check_fields(year, month, day, hour, minute, second)?;
        Ok(UtcTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            #[cfg(feature = "ber-time")]
            utc_offset_minutes,
            #[cfg(feature = "ber-time")]
            local: false,
        })
    }

    fn render(&self) -> Result<Render, ValueError> {
        check_fields(self.year, self.month, self.day, self.hour, self.minute, self.second)?;
        #[cfg(feature = "ber-time")]
        if self.utc_offset_minutes.is_some() || self.local {
            return Err(ValueError::InvalidTime);
        }
        if !(1950..=2049).contains(&self.year) {
            return Err(ValueError::InvalidTime);
        }
        let mut r = Render::new();
        r.digits(u32::from(self.year % 100), 2)?;
        for v in [self.month, self.day, self.hour, self.minute, self.second] {
            r.digits(u32::from(v), 2)?;
        }
        r.push(b'Z')?;
        Ok(r)
    }
}

fixed_tag!(UtcTime, Tag::UTC_TIME);

impl<'a> ContentCodec<'a> for UtcTime {
    const MAX_COPY_LEN: usize = 17;

    fn decode_content(content: &'a [u8], rules: Rules) -> Result<Self, ValueError> {
        UtcTime::parse(content, rules)
    }

    fn decode_from_copy(content: &[u8], rules: Rules) -> Result<Self, ValueError> {
        UtcTime::parse(content, rules)
    }

    fn content_len(&self) -> usize {
        self.render().map_or(0, |r| r.len)
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.render().map_err(|e| Error::value(e, 0))?.write_to(out)
    }
}

/// A GeneralizedTime with calendar fields.
///
/// The day check uses the Gregorian leap-year rule for every year from 0000 to 9999. More
/// than nine fraction digits is invalid.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct GeneralizedTime {
    /// The four-digit year.
    pub year: u16,
    /// The month, 1–12.
    pub month: u8,
    /// The day of the month.
    pub day: u8,
    /// The hour, 0–23.
    pub hour: u8,
    /// The minute, 0–59.
    pub minute: u8,
    /// The second, 0–59.
    pub second: u8,
    /// The fraction of a second in nanoseconds.
    pub nanos: u32,
    /// The offset from UTC in minutes, when the BER form carried one.
    #[cfg(feature = "ber-time")]
    pub utc_offset_minutes: Option<i16>,
    /// Whether the BER form was local time with no UTC relation.
    #[cfg(feature = "ber-time")]
    pub local: bool,
}

impl GeneralizedTime {
    fn parse_der_grammar(content: &[u8], rules: Rules) -> Result<Self, ValueError> {
        let mut cur = Cursor::new(content);
        let year = cur.digits(4)? as u16;
        let (month, day, hour, minute, second) =
            (cur.two()?, cur.two()?, cur.two()?, cur.two()?, cur.two()?);
        let mut nanos = 0u32;
        if cur.peek() == Some(b'.') {
            cur.take();
            let mut digits = 0u32;
            let mut last = b'0';
            while cur.peek_digit() {
                digits += 1;
                if digits > 9 {
                    return Err(ValueError::InvalidTime);
                }
                last = cur.take().unwrap_or(b'0');
                nanos += u32::from(last - b'0') * 10u32.pow(9 - digits);
            }
            if digits == 0 || (rules == Rules::Der && last == b'0') {
                return Err(ValueError::InvalidTime);
            }
        }
        if cur.take() != Some(b'Z') {
            return Err(ValueError::InvalidTime);
        }
        cur.finish()?;
        check_fields(year, month, day, hour, minute, second)?;
        Ok(GeneralizedTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanos,
            #[cfg(feature = "ber-time")]
            utc_offset_minutes: None,
            #[cfg(feature = "ber-time")]
            local: false,
        })
    }

    #[cfg(feature = "ber-time")]
    fn parse_ber_grammar(content: &[u8]) -> Result<Self, ValueError> {
        const HOUR_NS: u128 = 3_600_000_000_000;
        const MINUTE_NS: u128 = 60_000_000_000;
        const SECOND_NS: u128 = 1_000_000_000;
        let mut cur = Cursor::new(content);
        let year = cur.digits(4)? as u16;
        let (month, day, hour) = (cur.two()?, cur.two()?, cur.two()?);
        let mut finest = HOUR_NS;
        let mut minute = 0;
        let mut second = 0;
        if cur.peek_digit() {
            minute = cur.two()?;
            finest = MINUTE_NS;
            if cur.peek_digit() {
                second = cur.two()?;
                finest = SECOND_NS;
            }
        }
        let mut fraction_ns = 0u128;
        if matches!(cur.peek(), Some(b'.' | b',')) {
            cur.take();
            let (mut numerator, mut digits) = (0u128, 0u32);
            while cur.peek_digit() {
                digits += 1;
                if digits > 9 {
                    return Err(ValueError::InvalidTime);
                }
                numerator = numerator * 10 + u128::from(cur.take().unwrap_or(b'0') - b'0');
            }
            if digits == 0 {
                return Err(ValueError::InvalidTime);
            }
            fraction_ns = numerator * finest / 10u128.pow(digits);
        }
        let (mut minute, mut second) = (u32::from(minute), u32::from(second));
        if finest == HOUR_NS {
            minute = (fraction_ns / MINUTE_NS) as u32;
            fraction_ns %= MINUTE_NS;
        }
        if finest != SECOND_NS {
            second = (fraction_ns / SECOND_NS) as u32;
            fraction_ns %= SECOND_NS;
        }
        let (mut utc_offset_minutes, mut local) = (None, false);
        match cur.peek() {
            None => local = true,
            Some(b'Z') => {
                cur.take();
            }
            Some(_) => utc_offset_minutes = Some(cur.utc_offset(None)?),
        }
        cur.finish()?;
        let (minute, second) = (minute as u8, second as u8);
        check_fields(year, month, day, hour, minute, second)?;
        Ok(GeneralizedTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanos: fraction_ns as u32,
            utc_offset_minutes,
            local,
        })
    }

    fn parse(content: &[u8], rules: Rules) -> Result<Self, ValueError> {
        #[cfg(feature = "ber-time")]
        if ber_grammar(rules) {
            return Self::parse_ber_grammar(content);
        }
        Self::parse_der_grammar(content, rules)
    }

    fn render(&self) -> Result<Render, ValueError> {
        check_fields(self.year, self.month, self.day, self.hour, self.minute, self.second)?;
        #[cfg(feature = "ber-time")]
        if self.utc_offset_minutes.is_some() || self.local {
            return Err(ValueError::InvalidTime);
        }
        if self.nanos > 999_999_999 {
            return Err(ValueError::InvalidTime);
        }
        let mut r = Render::new();
        r.digits(u32::from(self.year), 4)?;
        for v in [self.month, self.day, self.hour, self.minute, self.second] {
            r.digits(u32::from(v), 2)?;
        }
        if self.nanos != 0 {
            r.push(b'.')?;
            let mut shown = 9;
            let mut n = self.nanos;
            while n.is_multiple_of(10) {
                n /= 10;
                shown -= 1;
            }
            r.digits(n, shown)?;
        }
        r.push(b'Z')?;
        Ok(r)
    }
}

fixed_tag!(GeneralizedTime, Tag::GENERALIZED_TIME);

impl<'a> ContentCodec<'a> for GeneralizedTime {
    const MAX_COPY_LEN: usize = 29;

    fn decode_content(content: &'a [u8], rules: Rules) -> Result<Self, ValueError> {
        GeneralizedTime::parse(content, rules)
    }

    fn decode_from_copy(content: &[u8], rules: Rules) -> Result<Self, ValueError> {
        GeneralizedTime::parse(content, rules)
    }

    fn content_len(&self) -> usize {
        self.render().map_or(0, |r| r.len)
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.render().map_err(|e| Error::value(e, 0))?.write_to(out)
    }
}
