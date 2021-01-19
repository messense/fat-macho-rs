use std::{error, fmt};

#[derive(Debug)]
pub enum Error {
    ReadObject(object::read::Error),
    NotFatBinary,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ReadObject(err) => err.fmt(f),
            Error::NotFatBinary => write!(f, "input is not a valid Mach-O fat binary"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::ReadObject(err) => Some(err),
            Error::NotFatBinary => None,
        }
    }
}

impl From<object::read::Error> for Error {
    fn from(err: object::read::Error) -> Self {
        Self::ReadObject(err)
    }
}
