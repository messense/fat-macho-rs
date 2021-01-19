use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ReadObject(object::read::Error),
    NotFatBinary,
    InvalidMachO(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::ReadObject(err) => err.fmt(f),
            Error::NotFatBinary => write!(f, "input is not a valid Mach-O fat binary"),
            Error::InvalidMachO(err) => write!(f, "{}", err),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::ReadObject(err) => Some(err),
            Error::NotFatBinary => None,
            Error::InvalidMachO(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<object::read::Error> for Error {
    fn from(err: object::read::Error) -> Self {
        Self::ReadObject(err)
    }
}
