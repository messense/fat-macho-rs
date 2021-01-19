// Ported from https://github.com/randall77/makefat/blob/master/makefat.go
use std::io::Write;

use goblin::{
    mach::{fat::FAT_MAGIC, Mach, MachO},
    Object,
};

use crate::error::Error;

const FAT_MAGIC_64: u32 = FAT_MAGIC + 1;
const ALIGN_BITS: u32 = 14;

#[derive(Debug)]
struct ThinArch<'a> {
    data: &'a [u8],
    macho: MachO<'a>,
    offset: i64,
}

/// Mach-O fat binary writer
#[derive(Debug)]
pub struct FatWriter<'a> {
    arches: Vec<ThinArch<'a>>,
    offset: i64,
}

impl<'a> FatWriter<'a> {
    /// Create a new Mach-O fat binary writer
    pub fn new() -> Self {
        Self {
            arches: Vec::new(),
            offset: 0,
        }
    }

    pub fn add(&mut self, bytes: &'a [u8]) -> Result<(), Error> {
        match Object::parse(&bytes)? {
            Object::Mach(mach) => match mach {
                Mach::Fat(_) => todo!(),
                Mach::Binary(obj) => {
                    let align = 1 << ALIGN_BITS as i64;
                    if self.offset == 0 {
                        self.offset += align;
                    }
                    let thin = ThinArch {
                        data: bytes,
                        macho: obj,
                        offset: self.offset,
                    };
                    self.arches.push(thin);
                    self.offset += bytes.len() as i64;
                    self.offset = (self.offset + align - 1) / align * align;
                }
            },
            _ => return Err(Error::InvalidMachO("input is not a macho file".to_string())),
        }
        Ok(())
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        if self.arches.is_empty() {
            return Ok(());
        }
        // Check whether we're doing fat32 or fat64
        let is_64_bit = if self.offset >= 1i64 << 32
            || self.arches.last().unwrap().data.len() as i64 >= 1i64 << 32
        {
            true
        } else {
            false
        };
        let mut hdr = Vec::with_capacity(12);
        // Build a fat_header
        if is_64_bit {
            hdr.push(FAT_MAGIC_64);
        } else {
            hdr.push(FAT_MAGIC);
        }
        hdr.push(self.arches.len() as u32);
        // Build a fat_arch for each arch
        for arch in &self.arches {
            hdr.push(arch.macho.header.cputype);
            hdr.push(arch.macho.header.cpusubtype);
            if is_64_bit {
                // Big Endian
                hdr.push((arch.offset >> 32) as u32);
            }
            hdr.push(arch.offset as u32);
            if is_64_bit {
                hdr.push((arch.data.len() >> 32) as u32);
            }
            hdr.push(arch.data.len() as u32);
            hdr.push(ALIGN_BITS);
            if is_64_bit {
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
        for arch in &self.arches {
            if offset < arch.offset {
                writer.write_all(&vec![0; (arch.offset - offset) as usize])?;
                offset = arch.offset;
            }
            writer.write_all(&arch.data)?;
            offset += arch.data.len() as i64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FatWriter;
    use crate::read::FatReader;

    #[test]
    fn test_fat_writer_exe() {
        use std::fs;

        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        fat.add(&f1).unwrap();
        fat.add(&f2).unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());

        let mut out = fs::File::create("fat2").unwrap();
        fat.write_to(&mut out).unwrap();
    }
}
