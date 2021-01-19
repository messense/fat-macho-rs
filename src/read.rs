use std::fmt;

use object::read::macho::{FatArch as _, FatArch32, FatArch64, FatHeader};

use crate::error::Error;

#[derive(Debug, Clone, Copy)]
enum FatArch {
    FatArch32(FatArch32),
    FatArch64(FatArch64),
}

/// Mach-O FAT binary reader
#[derive(Clone)]
pub struct FatReader<'a> {
    buffer: &'a [u8],
    arches: Vec<FatArch>,
}

impl<'a> fmt::Debug for FatReader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FatReader")
            .field("arches", &self.arches)
            .finish()
    }
}

impl<'a> FatReader<'a> {
    /// Parse a Mach-O FAT binary from a buffer
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        if let Ok(arches) = FatHeader::parse_arch32(buffer) {
            let arches: Vec<FatArch> = arches
                .iter()
                .map(|arch| FatArch::FatArch32(arch.clone()))
                .collect();
            Ok(Self { buffer, arches })
        } else if let Ok(arches) = FatHeader::parse_arch64(buffer) {
            let arches: Vec<FatArch> = arches
                .iter()
                .map(|arch| FatArch::FatArch64(arch.clone()))
                .collect();
            Ok(Self { buffer, arches })
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

    #[test]
    fn test_fat_reader_dylib() {
        let buf = fs::read("tests/fixtures/simplefat.dylib").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        println!("{:#?}", reader);
    }

    #[test]
    fn test_fat_reader_exe() {
        let buf = fs::read("tests/fixtures/simplefat").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        println!("{:#?}", reader);
    }

    #[test]
    fn test_fat_reader_ar() {
        let buf = fs::read("tests/fixtures/simplefat.a").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        println!("{:#?}", reader);
    }
}
