// Ported from https://github.com/randall77/makefat/blob/master/makefat.go
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use goblin::{
    mach::{
        cputype::{
            get_arch_from_flag, get_arch_name_from_types, CpuSubType, CpuType, CPU_TYPE_ARM,
            CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_HPPA, CPU_TYPE_I386, CPU_TYPE_I860,
            CPU_TYPE_MC680X0, CPU_TYPE_MC88000, CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64,
            CPU_TYPE_SPARC, CPU_TYPE_X86_64,
        },
        fat::FAT_MAGIC,
        Mach, MachO,
    },
    Object,
};

use crate::error::Error;
use std::cmp::Ordering;

const FAT_MAGIC_64: u32 = FAT_MAGIC + 1;

#[derive(Debug)]
struct ThinArch<'a> {
    data: &'a [u8],
    macho: MachO<'a>,
    align: i64,
}

/// Mach-O fat binary writer
#[derive(Debug)]
pub struct FatWriter<'a> {
    arches: Vec<ThinArch<'a>>,
    max_align: i64,
}

impl<'a> FatWriter<'a> {
    /// Create a new Mach-O fat binary writer
    pub fn new() -> Self {
        Self {
            arches: Vec::new(),
            max_align: 0,
        }
    }

    /// Add a new thin Mach-O binary
    pub fn add(&mut self, bytes: &'a [u8]) -> Result<(), Error> {
        match Object::parse(&bytes)? {
            Object::Mach(mach) => match mach {
                Mach::Fat(_) => todo!(),
                Mach::Binary(obj) => {
                    let align = get_align_from_cpu_types(obj.header.cputype, obj.header.cpusubtype);
                    if align > self.max_align {
                        self.max_align = align;
                    }
                    let thin = ThinArch {
                        data: bytes,
                        macho: obj,
                        align,
                    };
                    self.arches.push(thin);
                }
            },
            _ => return Err(Error::InvalidMachO("input is not a macho file".to_string())),
        }
        // Sort the files by alignment to save space in ouput
        self.arches.sort_by(|a, b| {
            if a.macho.header.cputype == b.macho.header.cputype {
                // if cpu types match, sort by cpu subtype
                return a.macho.header.cpusubtype.cmp(&b.macho.header.cpusubtype);
            }
            // force arm64-family to follow after all other slices
            if a.macho.header.cputype == CPU_TYPE_ARM64 {
                return Ordering::Greater;
            }
            if b.macho.header.cputype == CPU_TYPE_ARM64 {
                return Ordering::Less;
            }
            a.align.cmp(&b.align)
        });
        Ok(())
    }

    /// Remove an architecture
    pub fn remove(&mut self, arch: &str) -> Option<&'a [u8]> {
        if let Some((cpu_type, cpu_subtype)) = get_arch_from_flag(arch) {
            if let Some(index) = self.arches.iter().position(|arch| {
                arch.macho.header.cputype == cpu_type && arch.macho.header.cpusubtype == cpu_subtype
            }) {
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
                .find(|arch| {
                    arch.macho.header.cputype == cpu_type
                        && arch.macho.header.cpusubtype == cpu_subtype
                })
                .is_some();
        }
        false
    }

    /// Write Mach-O fat binary into the writer
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        if self.arches.is_empty() {
            return Ok(());
        }
        let align = self.max_align;
        let mut total_offset = align;
        let mut arch_offsets = Vec::with_capacity(self.arches.len());
        for arch in &self.arches {
            arch_offsets.push(total_offset);
            total_offset += arch.data.len() as i64;
            total_offset = (total_offset + align - 1) / align * align;
        }
        // Check whether we're doing fat32 or fat64
        let is_fat64 = if total_offset >= 1i64 << 32
            || self.arches.last().unwrap().data.len() as i64 >= 1i64 << 32
        {
            true
        } else {
            false
        };
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
            hdr.push(arch.macho.header.cputype);
            hdr.push(arch.macho.header.cpusubtype);
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
    fn test_fat_writer_exe() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        fat.add(&f1).unwrap();
        fat.add(&f2).unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());

        fat.write_to_file("tests/output/fat").unwrap();
    }

    #[test]
    fn test_fat_writer_remove() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        fat.add(&f1).unwrap();
        fat.add(&f2).unwrap();
        let arm64 = fat.remove("arm64");
        assert!(arm64.is_some());
        assert!(fat.exists("x86_64"));
        assert!(!fat.exists("arm64"));
    }
}
