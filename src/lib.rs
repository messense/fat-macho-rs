//! Mach-O fat binary reader and writer
pub mod cputype;
mod error;
mod parse;
mod read;
mod write;

pub use self::error::Error;
pub use self::read::{FatArch, FatReader};
pub use self::write::FatWriter;
