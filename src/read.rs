use goblin::mach::{cputype::get_arch_from_flag, Mach, MultiArch};

use crate::error::Error;

/// Mach-O fat binary reader
#[derive(Debug)]
pub struct FatReader<'a> {
    buffer: &'a [u8],
    fat: MultiArch<'a>,
}

impl<'a> FatReader<'a> {
    /// Parse a Mach-O FAT binary from a buffer
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        match Mach::parse(buffer)? {
            Mach::Fat(fat) => Ok(Self { buffer, fat }),
            Mach::Binary(_) => Err(Error::NotFatBinary),
        }
    }

    /// Extract thin binary by arch name
    pub fn extract(&self, arch_name: &str) -> Option<&'a [u8]> {
        if let Some((cpu_type, _cpu_subtype)) = get_arch_from_flag(arch_name) {
            return self
                .fat
                .find_cputype(cpu_type)
                .unwrap_or_default()
                .map(|arch| arch.slice(self.buffer));
        }
        None
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
