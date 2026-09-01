use crate::cputype::{arch_from_name, arch_name, CpuSubType, CpuType};
use crate::error::Error;
use crate::parse::{
    classify, invalid, read_u32, read_u64_be, FatHeader, Kind, MachHeader, SIZEOF_FAT_HEADER,
};

/// One `fat_arch` / `fat_arch_64` entry of a fat binary
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatArch {
    /// `cputype` of the slice
    pub cpu_type: CpuType,
    /// `cpusubtype` of the slice, capability bits included
    pub cpu_subtype: CpuSubType,
    /// Offset of the slice from the start of the fat binary
    pub offset: u64,
    /// Size of the slice in bytes
    pub size: u64,
    /// Alignment of the slice as a power of 2
    pub align: u32,
}

impl FatArch {
    /// Parse one entry of the `fat_arch` table
    pub(crate) fn parse(entry: &[u8], is_fat64: bool) -> Option<Self> {
        let cpu_type = read_u32(entry, 0, false)?;
        let cpu_subtype = read_u32(entry, 4, false)?;
        let (offset, size, align) = if is_fat64 {
            (
                read_u64_be(entry, 8)?,
                read_u64_be(entry, 16)?,
                read_u32(entry, 24, false)?,
            )
        } else {
            (
                read_u32(entry, 8, false)? as u64,
                read_u32(entry, 12, false)? as u64,
                read_u32(entry, 16, false)?,
            )
        };
        Some(FatArch {
            cpu_type,
            cpu_subtype,
            offset,
            size,
            align,
        })
    }

    /// Architecture name, e.g. `x86_64` or `arm64e`, if known
    pub fn name(&self) -> Option<&'static str> {
        arch_name(self.cpu_type, self.cpu_subtype)
    }

    /// Whether this slice is the architecture called `arch_name`
    ///
    /// Like `lipo`, the subtype is compared as well, ignoring capability bits:
    /// an `arm64e` slice does not match `arm64`.
    pub fn is(&self, arch_name: &str) -> bool {
        match arch_from_name(arch_name) {
            Some((cpu_type, cpu_subtype)) => self.header().same_arch(cpu_type, cpu_subtype),
            None => false,
        }
    }

    #[inline]
    pub(crate) fn header(&self) -> MachHeader {
        MachHeader {
            cpu_type: self.cpu_type,
            cpu_subtype: self.cpu_subtype,
        }
    }

    /// Byte range of the slice, `None` on overflow
    #[inline]
    pub(crate) fn range(&self) -> Option<std::ops::Range<u64>> {
        Some(self.offset..self.offset.checked_add(self.size)?)
    }
}

/// Mach-O fat binary reader
///
/// Only the fat header and the `fat_arch` table are looked at; the slices
/// themselves are never parsed.
#[derive(Debug, Clone)]
pub struct FatReader<'a> {
    buffer: &'a [u8],
    header: FatHeader,
}

impl<'a> FatReader<'a> {
    /// Parse a Mach-O fat binary from a buffer
    ///
    /// Fails with [`Error::NotFatBinary`] for thin Mach-O binaries, archives
    /// and bitcode, and with [`Error::InvalidMachO`] for anything else or a
    /// fat header whose slices don't fit in the buffer.
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        match classify(&buffer[..buffer.len().min(crate::parse::HEAD_LEN)])? {
            Some(Kind::Fat) => {}
            Some(_) => return Err(Error::NotFatBinary),
            None => return Err(invalid("input is not a macho file")),
        }
        let header = FatHeader::parse(buffer).ok_or_else(|| invalid("truncated fat header"))?;
        // `parse` read the 8-byte header, so this can't underflow
        let rest = buffer.len() as u64 - SIZEOF_FAT_HEADER as u64;
        if rest < header.arch_table_len() {
            return Err(invalid("fat arch table runs past the end of the input"));
        }
        let reader = Self { buffer, header };
        if !reader
            .arches()
            .all(|arch| arch.range().is_some_and(|r| r.end <= buffer.len() as u64))
        {
            return Err(invalid("fat arch slice out of bounds"));
        }
        Ok(reader)
    }

    /// Whether the binary uses the 64-bit `fat_header` (`FAT_MAGIC_64`)
    pub fn is_fat64(&self) -> bool {
        self.header.is_fat64
    }

    /// Number of slices
    pub fn len(&self) -> usize {
        self.header.narches as usize
    }

    /// Whether the binary has no slices
    pub fn is_empty(&self) -> bool {
        self.header.narches == 0
    }

    /// The `fat_arch` table
    pub fn arches(&self) -> impl ExactSizeIterator<Item = FatArch> + DoubleEndedIterator + 'a {
        let is_fat64 = self.header.is_fat64;
        let table = &self.buffer[SIZEOF_FAT_HEADER..];
        table
            .chunks_exact(self.header.arch_size())
            .take(self.len())
            .map(move |entry| FatArch::parse(entry, is_fat64).unwrap())
    }

    /// Bytes of one slice
    pub fn slice(&self, arch: &FatArch) -> &'a [u8] {
        let range = arch.range().expect("slice bounds were checked in new()");
        &self.buffer[range.start as usize..range.end as usize]
    }

    /// Extract a thin binary by architecture name, e.g. `x86_64` or `arm64e`
    ///
    /// Like `lipo -thin`, the subtype must match too, ignoring capability
    /// bits: `arm64` does not extract an `arm64e` slice.
    pub fn extract(&self, arch_name: &str) -> Option<&'a [u8]> {
        let (cpu_type, cpu_subtype) = arch_from_name(arch_name)?;
        let arch = self
            .arches()
            .find(|arch| arch.header().same_arch(cpu_type, cpu_subtype))?;
        Some(self.slice(&arch))
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
        assert_eq!(2, reader.len());
        assert!(!reader.is_fat64());
        let names: Vec<_> = reader.arches().map(|a| a.name().unwrap()).collect();
        assert_eq!(names, ["x86_64", "arm64"]);
        for arch in reader.arches() {
            assert_eq!(reader.slice(&arch).len() as u64, arch.size);
            assert_eq!(arch.offset % (1 << arch.align), 0);
            assert!(arch.is(arch.name().unwrap()));
            assert!(!arch.is("arm64e"));
        }

        let buf = fs::read("tests/fixtures/hellofat").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        assert_eq!(3, reader.len());
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
    fn test_fat_reader_garbage() {
        assert!(matches!(
            FatReader::new(b"hello"),
            Err(Error::InvalidMachO(_))
        ));
        assert!(matches!(FatReader::new(b"\0"), Err(Error::InvalidMachO(_))));
        assert!(matches!(FatReader::new(b""), Err(Error::InvalidMachO(_))));
        // arch table claims more entries than the buffer holds
        let mut buf = fs::read("tests/fixtures/simplefat").unwrap();
        buf.truncate(8 + 20);
        assert!(matches!(FatReader::new(&buf), Err(Error::InvalidMachO(_))));
        // slice runs past the end of the buffer
        let mut buf = fs::read("tests/fixtures/simplefat").unwrap();
        buf[8 + 12..8 + 16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(FatReader::new(&buf), Err(Error::InvalidMachO(_))));
        // absurd nfat_arch must not allocate
        let mut buf = fs::read("tests/fixtures/simplefat").unwrap();
        buf[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(FatReader::new(&buf), Err(Error::InvalidMachO(_))));
    }

    #[test]
    fn test_fat_reader_extract_unknown_arch() {
        let buf = fs::read("tests/fixtures/simplefat").unwrap();
        let reader = FatReader::new(&buf).unwrap();
        assert!(reader.extract("not-an-arch").is_none());
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
}
