use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NotFatBinary,
    InvalidMachO(String),
    DuplicatedArch(String),
    #[cfg(feature = "bitcode")]
    Bitcode(llvm_bitcode::read::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::NotFatBinary => write!(f, "input is not a valid Mach-O fat binary"),
            Error::InvalidMachO(err) => write!(f, "{}", err),
            Error::DuplicatedArch(arch) => write!(f, "duplicated architecture {}", arch),
            #[cfg(feature = "bitcode")]
            Error::Bitcode(err) => err.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::NotFatBinary => None,
            Error::InvalidMachO(_) => None,
            Error::DuplicatedArch(_) => None,
            #[cfg(feature = "bitcode")]
            Error::Bitcode(err) => Some(err),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(feature = "bitcode")]
impl From<llvm_bitcode::read::Error> for Error {
    fn from(err: llvm_bitcode::read::Error) -> Self {
        Self::Bitcode(err)
    }
}
