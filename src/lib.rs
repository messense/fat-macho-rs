mod error;
mod read;
mod write;

pub use self::error::Error;
pub use self::read::FatReader;
pub use self::write::FatWriter;
