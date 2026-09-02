use goblin::mach::{cputype::get_arch_from_flag, MultiArch};

use crate::error::Error;
use crate::parse::{classify, invalid, same_arch, Kind, HEAD_LEN};

/// Mach-O fat binary reader
#[derive(Debug)]
pub struct FatReader<'a> {
    buffer: &'a [u8],
    fat: MultiArch<'a>,
}

impl<'a> FatReader<'a> {
    /// Parse a Mach-O FAT binary from a buffer
    ///
    /// Only the fat header is inspected; the individual slices are not parsed.
    /// Fat binaries with a 64-bit `fat_arch_64` table are rejected, goblin's
    /// [`MultiArch`] would misread them.
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        let magic = goblin::mach::peek(buffer, 0)?;
        match classify(&buffer[..buffer.len().min(HEAD_LEN)])? {
            Some(Kind::Fat { is_fat64: false }) => Ok(Self {
                buffer,
                fat: MultiArch::new(buffer)?,
            }),
            Some(Kind::Fat { is_fat64: true }) => {
                Err(invalid("64-bit fat binaries are not supported"))
            }
            Some(_) => Err(Error::NotFatBinary),
            None => Err(goblin::error::Error::BadMagic(u64::from(magic)).into()),
        }
    }

    /// Extract thin binary by arch name
    ///
    /// Like `lipo -thin`, the subtype must match too, ignoring capability
    /// bits: `arm64` does not extract an `arm64e` slice.
    pub fn extract(&self, arch_name: &str) -> Option<&'a [u8]> {
        let (cpu_type, cpu_subtype) = get_arch_from_flag(arch_name)?;
        let arch = self
            .fat
            .iter_arches()
            .map_while(Result::ok)
            .find(|arch| same_arch(arch.cputype, arch.cpusubtype, cpu_type, cpu_subtype))?;
        let start = arch.offset as usize;
        let end = start.checked_add(arch.size as usize)?;
        self.buffer.get(start..end)
    }
}

impl<'a> std::ops::Deref for FatReader<'a> {
    type Target = MultiArch<'a>;

    fn deref(&self) -> &Self::Target {
        &self.fat
    }
}

impl<'a> std::ops::DerefMut for FatReader<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.fat
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use goblin::Object;

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
        let reader = FatReader::new(&buf).unwrap();
        assert_eq!(2, reader.narches);

        let buf = fs::read("tests/fixtures/hellofat").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        assert_eq!(3, reader.narches);
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

        let buf = fs::read("tests/fixtures/thin_arm64.a").unwrap();
        assert!(matches!(FatReader::new(&buf), Err(Error::NotFatBinary)));
    }

    #[test]
    fn test_fat_reader_fat64_rejected() {
        // used to be handed to goblin, which read the 32-byte entries as
        // 20-byte ones and returned garbage slices
        let mut buf = fs::read("tests/fixtures/simplefat").unwrap();
        buf[..4].copy_from_slice(&crate::parse::FAT_MAGIC_64.to_be_bytes());
        assert!(matches!(FatReader::new(&buf), Err(Error::InvalidMachO(_))));
    }

    #[test]
    fn test_fat_reader_garbage() {
        assert!(matches!(FatReader::new(b"hello"), Err(Error::Goblin(_))));
        assert!(matches!(FatReader::new(b"\0"), Err(Error::Goblin(_))));
        // arch table claims more entries than the buffer holds
        let mut buf = fs::read("tests/fixtures/simplefat").unwrap();
        buf.truncate(8 + 20);
        let reader = FatReader::new(&buf).unwrap();
        assert!(reader.extract("x86_64").is_none());
        assert!(reader.extract("arm64").is_none());
        assert!(reader.extract("not-an-arch").is_none());
    }

    #[test]
    fn test_fat_reader_extract_subtype() {
        let buf = fs::read("tests/fixtures/simplefat").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        assert!(reader.extract("arm64").is_some());
        // arm64e is a different architecture, like `lipo -thin arm64e`
        assert!(reader.extract("arm64e").is_none());
        assert!(reader.extract("i386").is_none());
    }

    #[test]
    fn test_fat_reader_extract_dylib() {
        let buf = fs::read("tests/fixtures/simplefat.dylib").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        let x86_64 = reader.extract("x86_64").unwrap();
        let x86_64_obj = Object::parse(x86_64).unwrap();
        assert!(matches!(x86_64_obj, Object::Mach(_)));
        let arm64 = reader.extract("arm64").unwrap();
        let arm64_obj = Object::parse(arm64).unwrap();
        assert!(matches!(arm64_obj, Object::Mach(_)));
    }

    #[test]
    fn test_fat_reader_extract_exe() {
        let buf = fs::read("tests/fixtures/simplefat").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        let x86_64 = reader.extract("x86_64").unwrap();
        let x86_64_obj = Object::parse(x86_64).unwrap();
        assert!(matches!(x86_64_obj, Object::Mach(_)));
        let arm64 = reader.extract("arm64").unwrap();
        let arm64_obj = Object::parse(arm64).unwrap();
        assert!(matches!(arm64_obj, Object::Mach(_)));
    }

    #[test]
    fn test_fat_reader_extract_ar() {
        let buf = fs::read("tests/fixtures/simplefat.a").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        let x86_64 = reader.extract("x86_64").unwrap();
        let x86_64_obj = Object::parse(x86_64).unwrap();
        assert!(matches!(x86_64_obj, Object::Archive(_)));
        let arm64 = reader.extract("arm64").unwrap();
        let arm64_obj = Object::parse(arm64).unwrap();
        assert!(matches!(arm64_obj, Object::Archive(_)));
    }
}
