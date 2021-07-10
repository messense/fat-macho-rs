// Ported from https://github.com/randall77/makefat/blob/master/makefat.go
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    cmp::Ordering,
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
};

#[cfg(feature = "bitcode")]
use goblin::mach::cputype::{
    CPU_SUBTYPE_ARM64_32_ALL, CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_E, CPU_SUBTYPE_ARM_V4T,
    CPU_SUBTYPE_ARM_V5TEJ, CPU_SUBTYPE_ARM_V6, CPU_SUBTYPE_ARM_V6M, CPU_SUBTYPE_ARM_V7,
    CPU_SUBTYPE_ARM_V7EM, CPU_SUBTYPE_ARM_V7F, CPU_SUBTYPE_ARM_V7K, CPU_SUBTYPE_ARM_V7M,
    CPU_SUBTYPE_ARM_V7S, CPU_SUBTYPE_I386_ALL, CPU_SUBTYPE_POWERPC_ALL, CPU_SUBTYPE_X86_64_ALL,
    CPU_SUBTYPE_X86_64_H,
};
use goblin::{
    archive::Archive,
    mach::{
        cputype::{
            get_arch_from_flag, get_arch_name_from_types, CpuSubType, CpuType, CPU_ARCH_ABI64,
            CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_HPPA, CPU_TYPE_I386,
            CPU_TYPE_I860, CPU_TYPE_MC680X0, CPU_TYPE_MC88000, CPU_TYPE_POWERPC,
            CPU_TYPE_POWERPC64, CPU_TYPE_SPARC, CPU_TYPE_X86_64,
        },
        fat::{FAT_MAGIC, SIZEOF_FAT_ARCH, SIZEOF_FAT_HEADER},
        Mach,
    },
    Object,
};
#[cfg(feature = "bitcode")]
use llvm_bitcode::{bitcode::BitcodeElement, Bitcode};

use crate::error::Error;

const FAT_MAGIC_64: u32 = FAT_MAGIC + 1;
const SIZEOF_FAT_ARCH_64: usize = 32;

const LLVM_BITCODE_WRAPPER_MAGIC: u32 = 0x0B17C0DE;

#[derive(Debug)]
struct ThinArch {
    data: Vec<u8>,
    cpu_type: u32,
    cpu_subtype: u32,
    align: i64,
}

/// Mach-O fat binary writer
#[derive(Debug)]
pub struct FatWriter {
    arches: Vec<ThinArch>,
    max_align: i64,
    is_fat64: bool,
}

#[inline]
fn unpack_u32(buf: &[u8]) -> io::Result<u32> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "not enough data for unpacking u32",
        ));
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

impl FatWriter {
    /// Create a new Mach-O fat binary writer
    pub fn new() -> Self {
        Self {
            arches: Vec::new(),
            max_align: 0,
            is_fat64: false,
        }
    }

    /// Add a new thin Mach-O binary
    pub fn add<T: Into<Vec<u8>>>(&mut self, bytes: T) -> Result<(), Error> {
        let bytes = bytes.into();
        match Object::parse(&bytes)? {
            Object::Mach(mach) => match mach {
                Mach::Fat(fat) => {
                    for arch in fat.arches()? {
                        let buffer = arch.slice(&bytes);
                        self.add(buffer.to_vec())?;
                    }
                }
                Mach::Binary(obj) => {
                    let header = obj.header;
                    let cpu_type = header.cputype;
                    let cpu_subtype = header.cpusubtype;
                    // Check if this architecture already exists
                    if self
                        .arches
                        .iter()
                        .find(|arch| arch.cpu_type == cpu_type && arch.cpu_subtype == cpu_subtype)
                        .is_some()
                    {
                        let arch =
                            get_arch_name_from_types(cpu_type, cpu_subtype).unwrap_or("unknown");
                        return Err(Error::DuplicatedArch(arch.to_string()));
                    }
                    if header.magic == FAT_MAGIC_64 {
                        self.is_fat64 = true;
                    }
                    let align = get_align_from_cpu_types(cpu_type, cpu_subtype);
                    if align > self.max_align {
                        self.max_align = align;
                    }
                    let thin = ThinArch {
                        data: bytes,
                        cpu_type,
                        cpu_subtype,
                        align,
                    };
                    self.arches.push(thin);
                }
            },
            Object::Archive(ar) => {
                let (cpu_type, cpu_subtype) = self.check_archive(&bytes, &ar)?;
                let align = if cpu_type & CPU_ARCH_ABI64 != 0 {
                    8 /* alignof(u64) */
                } else {
                    4 /* alignof(u32) */
                };
                if align > self.max_align {
                    self.max_align = align;
                }
                let thin = ThinArch {
                    data: bytes,
                    cpu_type,
                    cpu_subtype,
                    align,
                };
                self.arches.push(thin);
            }
            Object::Unknown(_) => {
                let magic = unpack_u32(&bytes)?;
                if magic == LLVM_BITCODE_WRAPPER_MAGIC {
                    #[cfg(feature = "bitcode")]
                    {
                        let (cpu_type, cpu_subtype) = self.get_arch_from_bitcode(&bytes)?;
                        let align = 1;
                        if align > self.max_align {
                            self.max_align = align;
                        }
                        let thin = ThinArch {
                            data: bytes,
                            cpu_type,
                            cpu_subtype,
                            align,
                        };
                        self.arches.push(thin);
                    }

                    #[cfg(not(feature = "bitcode"))]
                    return Err(Error::InvalidMachO(
                        "bitcode input is unsupported".to_string(),
                    ));
                } else {
                    return Err(Error::InvalidMachO("input is not a macho file".to_string()));
                }
            }
            _ => return Err(Error::InvalidMachO("input is not a macho file".to_string())),
        }
        // Sort the files by alignment to save space in ouput
        self.arches.sort_by(|a, b| {
            if a.cpu_type == b.cpu_type {
                // if cpu types match, sort by cpu subtype
                return a.cpu_subtype.cmp(&b.cpu_subtype);
            }
            // force arm64-family to follow after all other slices
            if a.cpu_type == CPU_TYPE_ARM64 {
                return Ordering::Greater;
            }
            if b.cpu_type == CPU_TYPE_ARM64 {
                return Ordering::Less;
            }
            a.align.cmp(&b.align)
        });
        Ok(())
    }

    #[cfg(feature = "bitcode")]
    fn get_arch_from_bitcode(&self, buffer: &[u8]) -> Result<(CpuType, CpuSubType), Error> {
        let bitcode = Bitcode::new(buffer)?;
        let target_triple = bitcode
            .elements
            .iter()
            .find(|ele| match ele {
                BitcodeElement::Record(_) => false,
                BitcodeElement::Block(block) => block.id == 8,
            })
            .and_then(|module_block| {
                module_block
                    .as_block()
                    .unwrap()
                    .elements
                    .iter()
                    .find(|ele| match ele {
                        BitcodeElement::Record(record) => record.id == 2,
                        BitcodeElement::Block(_) => false,
                    })
            })
            .and_then(|target_triple_record| {
                let record = target_triple_record.as_record().unwrap();
                let fields: Vec<u8> = record.fields.iter().map(|x| *x as u8).collect();
                String::from_utf8(fields).ok()
            });
        if let Some(triple) = target_triple {
            if let Some(triple) = triple.splitn(2, "-").next() {
                return Ok(match triple {
                    "i686" | "i386" => (CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL),
                    "x86_64" => (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
                    "x86_64h" => (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H),
                    "powerpc" => (CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_ALL),
                    "powerpc64" => (CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_ALL),
                    "arm" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V4T),
                    "armv5" | "armv5e" | "thumbv5" | "thumbv5e" => {
                        (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V5TEJ)
                    }
                    "armv6" | "thumbv6" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6),
                    "armv6m" | "thumbv6m" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6M),
                    "armv7" | "thumbv7" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7),
                    "armv7f" | "thumbv7f" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7F),
                    "armv7s" | "thumbv7s" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S),
                    "armv7k" | "thumbv7k" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K),
                    "armv7m" | "thumbv7m" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7M),
                    "armv7em" | "thumbv7em" => (CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7EM),
                    "arm64" => (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
                    "arm64e" => (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E),
                    "arm64_32" => (CPU_TYPE_ARM64_32, CPU_SUBTYPE_ARM64_32_ALL),
                    _ => return Err(Error::InvalidMachO("input is not a macho file".to_string())),
                });
            }
        }
        Err(Error::InvalidMachO("input is not a macho file".to_string()))
    }

    fn check_archive(&self, buffer: &[u8], ar: &Archive) -> Result<(u32, u32), Error> {
        for member in ar.members() {
            let bytes = ar.extract(member, buffer)?;
            match Object::parse(bytes)? {
                Object::Mach(mach) => match mach {
                    Mach::Binary(obj) => {
                        return Ok((obj.header.cputype, obj.header.cpusubtype));
                    }
                    Mach::Fat(_) => {}
                },
                _ => {}
            }
        }
        Err(Error::InvalidMachO(
            "No Mach-O objects found in archivec".to_string(),
        ))
    }

    /// Remove an architecture
    pub fn remove(&mut self, arch: &str) -> Option<Vec<u8>> {
        if let Some((cpu_type, cpu_subtype)) = get_arch_from_flag(arch) {
            if let Some(index) = self
                .arches
                .iter()
                .position(|arch| arch.cpu_type == cpu_type && arch.cpu_subtype == cpu_subtype)
            {
                return Some(self.arches.remove(index).data);
            }
        }
        None
    }

    /// Check whether a certain architecture exists in this fat binary
    pub fn exists(&self, arch: &str) -> bool {
        if let Some((cpu_type, cpu_subtype)) = get_arch_from_flag(arch) {
            return self
                .arches
                .iter()
                .find(|arch| arch.cpu_type == cpu_type && arch.cpu_subtype == cpu_subtype)
                .is_some();
        }
        false
    }

    /// Write Mach-O fat binary into the writer
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        if self.arches.is_empty() {
            return Ok(());
        }
        // Check whether we're doing fat32 or fat64
        let is_fat64 =
            if self.is_fat64 || self.arches.last().unwrap().data.len() as i64 >= 1i64 << 32 {
                true
            } else {
                false
            };
        let align = self.max_align;
        let mut total_offset = SIZEOF_FAT_HEADER as i64;
        if is_fat64 {
            total_offset += self.arches.len() as i64 * SIZEOF_FAT_ARCH_64 as i64;
        // narches * size of fat_arch_64
        } else {
            total_offset += self.arches.len() as i64 * SIZEOF_FAT_ARCH as i64; // narches * size of fat_arch
        }
        let mut arch_offsets = Vec::with_capacity(self.arches.len());
        for arch in &self.arches {
            // Round up to multiple of align
            total_offset = (total_offset + align - 1) / align * align;
            arch_offsets.push(total_offset);
            total_offset += arch.data.len() as i64;
        }
        let mut hdr = Vec::with_capacity(12);
        // Build a fat_header
        if is_fat64 {
            hdr.push(FAT_MAGIC_64);
        } else {
            hdr.push(FAT_MAGIC);
        }
        hdr.push(self.arches.len() as u32);
        // Compute the max alignment bits
        let align_bits = (align as f32).log2() as u32;
        // Build a fat_arch for each arch
        for (arch, arch_offset) in self.arches.iter().zip(arch_offsets.iter()) {
            hdr.push(arch.cpu_type);
            hdr.push(arch.cpu_subtype);
            if is_fat64 {
                // Big Endian
                hdr.push((arch_offset >> 32) as u32);
            }
            hdr.push(*arch_offset as u32);
            if is_fat64 {
                hdr.push((arch.data.len() >> 32) as u32);
            }
            hdr.push(arch.data.len() as u32);
            hdr.push(align_bits);
            if is_fat64 {
                // Reserved
                hdr.push(0);
            }
        }
        // Write header
        // Note that the fat binary header is big-endian, regardless of the
        // endianness of the contained files.
        for i in &hdr {
            writer.write_all(&i.to_be_bytes())?;
        }
        let mut offset = 4 * hdr.len() as i64;
        // Write each arch
        for (arch, arch_offset) in self.arches.iter().zip(arch_offsets) {
            if offset < arch_offset {
                writer.write_all(&vec![0; (arch_offset - offset) as usize])?;
                offset = arch_offset;
            }
            writer.write_all(&arch.data)?;
            offset += arch.data.len() as i64;
        }
        Ok(())
    }

    /// Write Mach-O fat binary to a file
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let file = File::create(path)?;
        #[cfg(unix)]
        {
            let mut perm = file.metadata()?.permissions();
            perm.set_mode(0o755);
            file.set_permissions(perm)?;
        }
        let mut writer = BufWriter::new(file);
        self.write_to(&mut writer)?;
        Ok(())
    }
}

fn get_align_from_cpu_types(cpu_type: CpuType, cpu_subtype: CpuSubType) -> i64 {
    if let Some(arch_name) = get_arch_name_from_types(cpu_type, cpu_subtype) {
        if let Some((cpu_type, _)) = get_arch_from_flag(arch_name) {
            match cpu_type {
                // embedded
                CPU_TYPE_ARM | CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => return 0x4000,
                // desktop
                CPU_TYPE_X86_64 | CPU_TYPE_I386 | CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 => {
                    return 0x1000
                }
                CPU_TYPE_MC680X0 | CPU_TYPE_MC88000 | CPU_TYPE_SPARC | CPU_TYPE_I860
                | CPU_TYPE_HPPA => return 0x2000,
                _ => {}
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::FatWriter;
    use crate::read::FatReader;

    #[test]
    fn test_fat_writer_add_exe() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());

        fat.write_to_file("tests/output/fat").unwrap();
    }

    #[test]
    fn test_fat_writer_add_duplicated_arch() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        fat.add(f1.clone()).unwrap();
        assert!(fat.add(f1).is_err());
    }

    #[test]
    fn test_fat_writer_add_fat() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/simplefat").unwrap();
        fat.add(f1).unwrap();
        assert!(fat.exists("x86_64"));
        assert!(fat.exists("arm64"));
    }

    #[test]
    fn test_fat_writer_add_archive() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64.a").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64.a").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());

        fat.write_to_file("tests/output/fat.a").unwrap();
    }

    #[cfg(feature = "bitcode")]
    #[test]
    fn test_fat_writer_add_llvm_bitcode() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64.bc").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64.bc").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());

        fat.write_to_file("tests/output/fat_bc").unwrap();
    }

    #[test]
    fn test_fat_writer_remove() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        let arm64 = fat.remove("arm64");
        assert!(arm64.is_some());
        assert!(fat.exists("x86_64"));
        assert!(!fat.exists("arm64"));
    }
}
