//! Cheap, header-only classification of input files.
//!
//! Everything here looks at a handful of bytes at the start of a buffer; no
//! load commands, symbol tables or archive indexes are ever parsed. Input is
//! read through the [`Source`] trait so that the same code serves in-memory
//! buffers and files on disk.
use std::fs::File;
use std::io;

use crate::cputype::{arch_name, strip_cpu_subtype_caps, CpuSubType, CpuType};
use crate::error::Error;

/// `mach_header` magic, big-endian / little-endian, 32 / 64-bit
pub(crate) const MH_MAGIC: u32 = 0xfeed_face;
pub(crate) const MH_CIGAM: u32 = MH_MAGIC.swap_bytes();
pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(crate) const MH_CIGAM_64: u32 = MH_MAGIC_64.swap_bytes();
/// `fat_header` magic; fat headers are always big-endian
pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// Magic of the LLVM bitcode wrapper header, as a little-endian `u32`
pub(crate) const LLVM_BITCODE_WRAPPER_MAGIC: u32 = 0x0B17_C0DE;
/// `ar` archive magic
pub(crate) const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

pub(crate) const SIZEOF_MACH_HEADER_32: usize = 28;
pub(crate) const SIZEOF_MACH_HEADER_64: usize = 32;
pub(crate) const SIZEOF_FAT_HEADER: usize = 8;
pub(crate) const SIZEOF_FAT_ARCH: usize = 20;
pub(crate) const SIZEOF_FAT_ARCH_64: usize = 32;
const SIZEOF_AR_HEADER: u64 = 60;

/// Bytes needed to classify any input: the largest header we look at
pub(crate) const HEAD_LEN: usize = SIZEOF_MACH_HEADER_64;

/// Random access to input bytes, either in memory or on disk
pub(crate) trait Source {
    fn len(&self) -> u64;

    /// Read into `buf` at `offset`, returning the number of bytes read.
    ///
    /// Reads past the end are short, exactly like `pread(2)`.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;

    /// Fill `buf` entirely from `offset`
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(buf, offset) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Read the first `HEAD_LEN` bytes (or fewer if the source is shorter)
    fn read_head(&self, head: &mut [u8; HEAD_LEN]) -> io::Result<usize> {
        let n = self.len().min(HEAD_LEN as u64) as usize;
        self.read_exact_at(&mut head[..n], 0)?;
        Ok(n)
    }
}

impl Source for [u8] {
    #[inline]
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    #[inline]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let start = offset.min(<[u8]>::len(self) as u64) as usize;
        let n = buf.len().min(<[u8]>::len(self) - start);
        buf[..n].copy_from_slice(&self[start..start + n]);
        Ok(n)
    }
}

/// Positional read on a file, without touching its cursor
#[inline]
pub(crate) fn file_read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}

/// The few `mach_header` fields we need
#[derive(Debug, Clone, Copy)]
pub(crate) struct MachHeader {
    pub(crate) cpu_type: CpuType,
    /// Raw `cpusubtype` from the Mach-O header, capability bits included,
    /// so that they are preserved in the written `fat_arch` entry.
    pub(crate) cpu_subtype: CpuSubType,
}

impl MachHeader {
    /// Compare architectures ignoring the capability bits of `cpusubtype`
    #[inline]
    pub(crate) fn same_arch(&self, cpu_type: CpuType, cpu_subtype: CpuSubType) -> bool {
        self.cpu_type == cpu_type
            && strip_cpu_subtype_caps(self.cpu_subtype) == strip_cpu_subtype_caps(cpu_subtype)
    }

    /// Human readable architecture name, e.g. `arm64e`
    pub(crate) fn arch_name(&self) -> &'static str {
        arch_name(self.cpu_type, self.cpu_subtype).unwrap_or("unknown")
    }
}

/// The `fat_header`
#[derive(Debug, Clone, Copy)]
pub(crate) struct FatHeader {
    pub(crate) is_fat64: bool,
    pub(crate) narches: u32,
}

impl FatHeader {
    /// Parse a `fat_header`, `None` if the magic isn't a fat magic
    pub(crate) fn parse(head: &[u8]) -> Option<Self> {
        let is_fat64 = match read_u32(head, 0, false)? {
            FAT_MAGIC => false,
            FAT_MAGIC_64 => true,
            _ => return None,
        };
        Some(FatHeader {
            is_fat64,
            narches: read_u32(head, 4, false)?,
        })
    }

    /// Size of one `fat_arch` / `fat_arch_64` entry
    #[inline]
    pub(crate) fn arch_size(&self) -> usize {
        fat_arch_size(self.is_fat64)
    }

    /// Byte range of the `fat_arch` table
    pub(crate) fn arch_table_len(&self) -> u64 {
        self.narches as u64 * self.arch_size() as u64
    }
}

/// Size of a `fat_arch` / `fat_arch_64` entry
#[inline]
pub(crate) fn fat_arch_size(is_fat64: bool) -> usize {
    if is_fat64 {
        SIZEOF_FAT_ARCH_64
    } else {
        SIZEOF_FAT_ARCH
    }
}

/// What kind of file a buffer holds, judged by its magic
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    /// Thin Mach-O binary
    Thin(MachHeader),
    /// Mach-O fat binary
    Fat,
    /// `ar` static archive
    Archive,
    /// LLVM bitcode with a wrapper header
    Bitcode,
}

/// Read a `u32` at `offset`, `None` if the buffer is too short
#[inline]
pub(crate) fn read_u32(buf: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?.try_into().ok()?;
    Some(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

/// Read a big-endian `u64` at `offset`, `None` if the buffer is too short
#[inline]
pub(crate) fn read_u64_be(buf: &[u8], offset: usize) -> Option<u64> {
    let bytes = buf.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

pub(crate) fn invalid(msg: &str) -> Error {
    Error::InvalidMachO(msg.to_string())
}

/// Classify a file by its magic number
///
/// `head` is the start of the file, at most [`HEAD_LEN`] bytes. Returns
/// `Ok(None)` if the magic isn't recognized. Thin Mach-O headers are parsed
/// on the spot, which is the only case that can fail.
pub(crate) fn classify(head: &[u8]) -> Result<Option<Kind>, Error> {
    // Magic numbers are stored in the endianness of the file; reading them
    // big-endian tells us which endianness the rest of the header uses.
    const BITCODE_MAGIC_BE: u32 = LLVM_BITCODE_WRAPPER_MAGIC.swap_bytes();
    let Some(magic) = read_u32(head, 0, false) else {
        return Ok(None);
    };
    let (little_endian, header_size) = match magic {
        MH_MAGIC => (false, SIZEOF_MACH_HEADER_32),
        MH_CIGAM => (true, SIZEOF_MACH_HEADER_32),
        MH_MAGIC_64 => (false, SIZEOF_MACH_HEADER_64),
        MH_CIGAM_64 => (true, SIZEOF_MACH_HEADER_64),
        FAT_MAGIC | FAT_MAGIC_64 => return Ok(Some(Kind::Fat)),
        BITCODE_MAGIC_BE => return Ok(Some(Kind::Bitcode)),
        _ if head.starts_with(AR_MAGIC) => return Ok(Some(Kind::Archive)),
        _ => return Ok(None),
    };
    if head.len() < header_size {
        return Err(invalid("bytes size is smaller than a Mach-O header"));
    }
    Ok(Some(Kind::Thin(MachHeader {
        cpu_type: read_u32(head, 4, little_endian).unwrap(),
        cpu_subtype: read_u32(head, 8, little_endian).unwrap(),
    })))
}

/// Parse a space padded decimal field of an `ar` member header
fn ar_field(field: &[u8]) -> Option<u64> {
    let end = field
        .iter()
        .position(|&b| b == b' ' || b == 0)
        .unwrap_or(field.len());
    let digits = &field[..end];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &b| {
        acc.checked_mul(10)?.checked_add((b - b'0') as u64)
    })
}

/// Find the architecture of the first Mach-O object in an `ar` archive.
///
/// Walks the member headers only, without touching the symbol table or the
/// long name index, and stops at the first member that is a thin Mach-O.
pub(crate) fn archive_arch<S: Source + ?Sized>(src: &S) -> Result<MachHeader, Error> {
    let len = src.len();
    let mut offset = AR_MAGIC.len() as u64;
    let mut hdr = [0u8; SIZEOF_AR_HEADER as usize];
    let mut head = [0u8; HEAD_LEN];
    let malformed = || invalid("malformed archive");
    while offset < len {
        if len - offset < SIZEOF_AR_HEADER {
            return Err(malformed());
        }
        src.read_exact_at(&mut hdr, offset)?;
        if &hdr[58..60] != b"`\n" {
            return Err(malformed());
        }
        let size = ar_field(&hdr[48..58]).ok_or_else(malformed)?;
        let mut data = offset + SIZEOF_AR_HEADER;
        let mut data_len = size;
        // BSD long name: `#1/N`, the N-byte name precedes the data and is
        // counted in the size
        if let Some(name_len) = hdr.strip_prefix(b"#1/") {
            let name_len = ar_field(&name_len[..13]).ok_or_else(malformed)?;
            if name_len > size {
                return Err(malformed());
            }
            data += name_len;
            data_len -= name_len;
        }
        let end = data
            .checked_add(data_len)
            .filter(|&end| end <= len)
            .ok_or_else(malformed)?;
        let n = data_len.min(HEAD_LEN as u64) as usize;
        src.read_exact_at(&mut head[..n], data)?;
        if let Some(Kind::Thin(header)) = classify(&head[..n])? {
            return Ok(header);
        }
        // members are 2-byte aligned
        offset = end + (end & 1);
    }
    Err(invalid("No Mach-O objects found in archive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ar_field() {
        assert_eq!(ar_field(b"1234      "), Some(1234));
        assert_eq!(ar_field(b"0         "), Some(0));
        assert_eq!(ar_field(b"          "), None);
        assert_eq!(ar_field(b"12a4      "), None);
        assert_eq!(ar_field(b"99999999999999999999"), None);
    }

    #[test]
    fn test_slice_source() {
        let data = [1u8, 2, 3, 4, 5];
        let src: &[u8] = &data;
        let mut buf = [0u8; 4];
        assert_eq!(src.read_at(&mut buf, 3).unwrap(), 2);
        assert_eq!(&buf[..2], &[4, 5]);
        assert_eq!(src.read_at(&mut buf, 10).unwrap(), 0);
        assert!(src.read_exact_at(&mut buf, 3).is_err());
        let mut head = [0u8; HEAD_LEN];
        assert_eq!(src.read_head(&mut head).unwrap(), 5);
        assert_eq!(&head[..5], &data);
    }
}
