use std::fmt::{Display, Formatter};

pub type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Debug)]
pub struct DecodeError;

impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("decode failed")
    }
}

impl std::error::Error for DecodeError {}
