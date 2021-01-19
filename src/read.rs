use goblin::mach::{fat::FAT_MAGIC, MultiArch};

use crate::error::Error;

/// Mach-O fat binary reader
#[derive(Debug)]
pub struct FatReader<'a> {
    fat: MultiArch<'a>,
}

impl<'a> FatReader<'a> {
    /// Parse a Mach-O FAT binary from a buffer
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        // globin MultiArch::new has bug
        // MultiArchthread 'read::test::test_fat_reader_not_fat' panicked at 'called `Result::unwrap()` on an `Err` value: Scroll(BadOffset(8))',
        // goblin-0.3.1/src/mach/mod.rs:413:45
        let (magic, _) = goblin::mach::parse_magic_and_ctx(buffer, 0)?;
        if magic != FAT_MAGIC && magic != FAT_MAGIC + 1 {
            return Err(Error::NotFatBinary);
        }
        if let Ok(fat) = MultiArch::new(buffer) {
            Ok(Self { fat })
        } else {
            Err(Error::NotFatBinary)
        }
    }

    /// Extract thin binary by arch name
    pub fn extract(&self, arch_name: &str) -> Option<&'a [u8]> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::FatReader;
    use crate::error::Error;

    #[test]
    fn test_fat_reader_dylib() {
        let buf = fs::read("tests/fixtures/simplefat.dylib").unwrap();
        let reader = FatReader::new(&buf);
        assert!(reader.is_ok());
    }

    #[test]
    fn test_fat_reader_exe() {
        let buf = fs::read("tests/fixtures/simplefat").unwrap();
        let reader = FatReader::new(&buf);
        assert!(reader.is_ok());
    }

    #[test]
    fn test_fat_reader_ar() {
        let buf = fs::read("tests/fixtures/simplefat.a").unwrap();
        let reader = FatReader::new(&buf);
        assert!(reader.is_ok());
    }

    #[test]
    fn test_fat_reader_not_fat() {
        let buf = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let reader = FatReader::new(&buf);
        assert!(reader.is_err());
        assert!(matches!(reader.unwrap_err(), Error::NotFatBinary));

        let buf = fs::read("tests/fixtures/thin_arm64").unwrap();
        let reader = FatReader::new(&buf);
        assert!(reader.is_err());
        assert!(matches!(reader.unwrap_err(), Error::NotFatBinary));
    }
}
