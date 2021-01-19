// Ported from https://github.com/randall77/makefat/blob/master/makefat.go
use std::io::Write;

use object::macho::{FAT_MAGIC, FAT_MAGIC_64, MH_MAGIC, MH_MAGIC_64};

use crate::error::Error;

const ALIGN_BITS: u32 = 12;
const ALIGN: i64 = 1 << ALIGN_BITS as i64;

#[derive(Debug)]
struct MachO {
    data: Vec<u8>,
    cpu_type: u32,
    cpu_subtype: u32,
    offset: i64,
}

/// Mach-O fat binary writer
#[derive(Debug)]
pub struct FatWriter {
    arches: Vec<MachO>,
    offset: i64,
}

impl FatWriter {
    /// Create a new Mach-O fat binary writer
    pub fn new() -> Self {
        Self {
            arches: Vec::new(),
            offset: ALIGN,
        }
    }

    pub fn add(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let input_len = bytes.len();
        if input_len < 12 {
            return Err(Error::InvalidMachO("input too small".to_string()));
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != MH_MAGIC && magic != MH_MAGIC_64 {
            return Err(Error::InvalidMachO(format!(
                "input is not a macho file, magic={:x}",
                magic
            )));
        }
        let cpu_type = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let cpu_subtype = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let macho = MachO {
            data: bytes,
            cpu_type,
            cpu_subtype,
            offset: self.offset,
        };
        self.arches.push(macho);
        self.offset += input_len as i64;
        self.offset = (self.offset + ALIGN - 1) / ALIGN * ALIGN;
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
            hdr.push(arch.cpu_type);
            hdr.push(arch.cpu_subtype);
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
        fat.add(fs::read("tests/fixtures/thin_x86_64").unwrap())
            .unwrap();
        fat.add(fs::read("tests/fixtures/thin_arm64").unwrap())
            .unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());
    }
}
