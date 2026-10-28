use super::{ContentCodec, fixed_tag};
use crate::util::write_slice;
use crate::{Error, Rules, Tag, ValueError};

fixed_tag!(bool, Tag::BOOLEAN);

impl<'a> ContentCodec<'a> for bool {
    fn decode_content(content: &'a [u8], rules: Rules) -> Result<Self, ValueError> {
        match content {
            [0x00] => Ok(false),
            [0xFF] => Ok(true),
            [_] if rules == Rules::Der => Err(ValueError::BooleanNotDer),
            [_] => Ok(true),
            _ => Err(ValueError::BooleanLength),
        }
    }

    fn content_len(&self) -> usize {
        1
    }

    fn encode_content(&self, out: &mut [u8]) -> Result<usize, Error> {
        write_slice(out, if *self { &[0xFF] } else { &[0x00] })
    }
}
