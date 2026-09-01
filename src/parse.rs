//! Cheap, header-only classification of input files.
//!
//! Everything here looks at a handful of bytes at the start of a buffer; no
//! load commands, symbol tables or archive indexes are ever parsed.
use goblin::{
    archive::{Member, MAGIC as AR_MAGIC},
    mach::{
        cputype::{get_arch_name_from_types, CpuSubType, CpuType, CPU_SUBTYPE_MASK},
        fat::FAT_MAGIC,
        header::{
            MH_CIGAM, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64, SIZEOF_HEADER_32, SIZEOF_HEADER_64,
        },
    },
};

use crate::error::Error;

/// Magic of the LLVM bitcode wrapper header, as a little-endian `u32`
pub(crate) const LLVM_BITCODE_WRAPPER_MAGIC: u32 = 0x0B17C0DE;

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
    pub(crate) fn same_arch(&self, cpu_type: CpuType, cpu_subtype: CpuSubType) -> bool {
        self.cpu_type == cpu_type
            && strip_cpu_subtype_caps(self.cpu_subtype) == strip_cpu_subtype_caps(cpu_subtype)
    }

    /// Human readable architecture name, e.g. `arm64e`
    pub(crate) fn arch_name(&self) -> &'static str {
        get_arch_name_from_types(self.cpu_type, strip_cpu_subtype_caps(self.cpu_subtype))
            .unwrap_or("unknown")
    }
}

/// Strip the capability bits (`CPU_SUBTYPE_MASK`, the high byte) from a `cpusubtype`.
///
/// Mach-O headers may carry feature flags in the high byte of `cpusubtype`,
/// e.g. `CPU_SUBTYPE_PTRAUTH_ABI` (`0x80000000`) on arm64e binaries, which
/// gives `cpusubtype == 0x80000002` instead of the bare `CPU_SUBTYPE_ARM64_E`.
/// Like `lipo`, we ignore those bits when identifying an architecture.
pub(crate) fn strip_cpu_subtype_caps(cpu_subtype: CpuSubType) -> CpuSubType {
    cpu_subtype & !CPU_SUBTYPE_MASK
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

/// Classify `buf` by its magic number
///
/// Returns `Ok(None)` if the magic isn't recognized. Thin Mach-O headers are
/// parsed on the spot, which is the only case that can fail.
pub(crate) fn classify(buf: &[u8]) -> Result<Option<Kind>, Error> {
    // Magic numbers are stored in the endianness of the file; reading them
    // big-endian tells us which endianness the rest of the header uses.
    const BITCODE_MAGIC_BE: u32 = LLVM_BITCODE_WRAPPER_MAGIC.swap_bytes();
    let Some(magic) = read_u32(buf, 0, false) else {
        return Ok(None);
    };
    let (little_endian, header_size) = match magic {
        MH_MAGIC => (false, SIZEOF_HEADER_32),
        MH_CIGAM => (true, SIZEOF_HEADER_32),
        MH_MAGIC_64 => (false, SIZEOF_HEADER_64),
        MH_CIGAM_64 => (true, SIZEOF_HEADER_64),
        FAT_MAGIC => return Ok(Some(Kind::Fat)),
        BITCODE_MAGIC_BE => return Ok(Some(Kind::Bitcode)),
        _ if buf.starts_with(AR_MAGIC) => return Ok(Some(Kind::Archive)),
        _ => return Ok(None),
    };
    if buf.len() < header_size {
        return Err(Error::InvalidMachO(
            "bytes size is smaller than a Mach-O header".to_string(),
        ));
    }
    Ok(Some(Kind::Thin(MachHeader {
        cpu_type: read_u32(buf, 4, little_endian).unwrap(),
        cpu_subtype: read_u32(buf, 8, little_endian).unwrap(),
    })))
}

/// Find the architecture of the first Mach-O object in an `ar` archive.
///
/// Walks the member headers only, without touching the symbol table or the
/// long name index, and stops at the first member that is a thin Mach-O.
pub(crate) fn archive_arch(buf: &[u8]) -> Result<MachHeader, Error> {
    let mut offset = AR_MAGIC.len();
    while offset < buf.len() {
        let member = Member::parse(buf, &mut offset)?;
        let start = member.offset as usize;
        let end = start
            .checked_add(member.size())
            .filter(|&end| end <= buf.len())
            .ok_or_else(|| Error::InvalidMachO("malformed archive".to_string()))?;
        if let Some(Kind::Thin(header)) = classify(&buf[start..end])? {
            return Ok(header);
        }
        // members are 2-byte aligned
        offset = end + (end & 1);
    }
    Err(Error::InvalidMachO(
        "No Mach-O objects found in archive".to_string(),
    ))
}
