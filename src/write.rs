// Ported from https://github.com/randall77/makefat/blob/master/makefat.go
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    borrow::Cow,
    cmp::Ordering,
    fmt,
    fs::File,
    io::{self, BufWriter, IoSlice, Write},
    ops::Range,
    path::Path,
    sync::Arc,
};

#[cfg(feature = "bitcode")]
use goblin::mach::cputype::{
    CPU_SUBTYPE_ARM64_32_ALL, CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_E, CPU_SUBTYPE_ARM_V4T,
    CPU_SUBTYPE_ARM_V5TEJ, CPU_SUBTYPE_ARM_V6, CPU_SUBTYPE_ARM_V6M, CPU_SUBTYPE_ARM_V7,
    CPU_SUBTYPE_ARM_V7EM, CPU_SUBTYPE_ARM_V7F, CPU_SUBTYPE_ARM_V7K, CPU_SUBTYPE_ARM_V7M,
    CPU_SUBTYPE_ARM_V7S, CPU_SUBTYPE_I386_ALL, CPU_SUBTYPE_POWERPC_ALL, CPU_SUBTYPE_X86_64_ALL,
    CPU_SUBTYPE_X86_64_H,
};
use goblin::mach::{
    cputype::{
        get_arch_from_flag, get_arch_name_from_types, CPU_ARCH_ABI64, CPU_TYPE_ARM, CPU_TYPE_ARM64,
        CPU_TYPE_ARM64_32, CPU_TYPE_HPPA, CPU_TYPE_I386, CPU_TYPE_I860, CPU_TYPE_MC680X0,
        CPU_TYPE_MC88000, CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64, CPU_TYPE_SPARC, CPU_TYPE_X86_64,
    },
    fat::{FAT_MAGIC, SIZEOF_FAT_ARCH, SIZEOF_FAT_HEADER},
    MultiArch,
};
#[cfg(feature = "bitcode")]
use llvm_bitcode::{bitcode::BitcodeElement, Bitcode};

use crate::error::Error;
use crate::parse::{archive_arch, classify, strip_cpu_subtype_caps, Kind, MachHeader};

const FAT_MAGIC_64: u32 = FAT_MAGIC + 1;
const SIZEOF_FAT_ARCH_64: usize = 32;

/// Largest slice alignment we ever use (the arm64 family's 2^14); the padding
/// between two slices is therefore always smaller than this.
const MAX_ALIGN: u64 = 0x4000;

/// Bytes backing one slice of the fat binary.
///
/// Input passed to [`FatWriter::add`] is never copied: borrowed input stays
/// borrowed, owned input is moved into a shared allocation so that all slices
/// of an owned fat binary can point into it.
enum ArchData<'a> {
    Borrowed(&'a [u8]),
    Shared(Arc<Vec<u8>>, Range<usize>),
}

impl<'a> ArchData<'a> {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            ArchData::Borrowed(data) => data,
            ArchData::Shared(data, range) => &data[range.clone()],
        }
    }

    /// Sub-slice of `self` without copying
    fn slice(&self, range: Range<usize>) -> Self {
        match self {
            ArchData::Borrowed(data) => ArchData::Borrowed(&data[range]),
            ArchData::Shared(data, base) => ArchData::Shared(
                data.clone(),
                base.start + range.start..base.start + range.end,
            ),
        }
    }

    fn into_cow(self) -> Cow<'a, [u8]> {
        match self {
            ArchData::Borrowed(data) => Cow::Borrowed(data),
            ArchData::Shared(data, range) => match Arc::try_unwrap(data) {
                // sole owner of the whole buffer: hand it back as is
                Ok(data) if range == (0..data.len()) => Cow::Owned(data),
                Ok(data) => Cow::Owned(data[range].to_vec()),
                Err(data) => Cow::Owned(data[range].to_vec()),
            },
        }
    }
}

impl<'a> From<Cow<'a, [u8]>> for ArchData<'a> {
    fn from(data: Cow<'a, [u8]>) -> ArchData<'a> {
        match data {
            Cow::Borrowed(data) => ArchData::Borrowed(data),
            Cow::Owned(data) => {
                let len = data.len();
                ArchData::Shared(Arc::new(data), 0..len)
            }
        }
    }
}

impl fmt::Debug for ArchData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            ArchData::Borrowed(_) => "Borrowed",
            ArchData::Shared(..) => "Shared",
        };
        write!(f, "{}({} bytes)", kind, self.as_slice().len())
    }
}

#[derive(Debug)]
struct ThinArch<'a> {
    data: ArchData<'a>,
    header: MachHeader,
    align: u64,
}

impl ThinArch<'_> {
    #[inline]
    fn len(&self) -> u64 {
        self.data.as_slice().len() as u64
    }
}

/// Size of a `fat_arch` / `fat_arch_64` entry
fn fat_arch_size(is_fat64: bool) -> usize {
    if is_fat64 {
        SIZEOF_FAT_ARCH_64
    } else {
        SIZEOF_FAT_ARCH
    }
}

/// Byte layout of the fat binary about to be written
struct Layout {
    is_fat64: bool,
    align_bits: u32,
    /// Offset of each slice, in the same order as `FatWriter::arches`
    offsets: Vec<u64>,
    /// Total size of the fat binary
    total_size: u64,
}

impl Layout {
    fn compute(sizes: &[u64], align: u64) -> Self {
        debug_assert!(align.is_power_of_two() && align <= MAX_ALIGN);
        let place = |is_fat64: bool| {
            let mut offset = (SIZEOF_FAT_HEADER + sizes.len() * fat_arch_size(is_fat64)) as u64;
            let mut offsets = Vec::with_capacity(sizes.len());
            for &size in sizes {
                offset = offset.next_multiple_of(align);
                offsets.push(offset);
                offset += size;
            }
            (offsets, offset)
        };
        // Try a 32-bit `fat_header` first; if any offset or size doesn't
        // fit in 32 bits fall back to the 64-bit variant, like `lipo`.
        let (mut offsets, mut total_size) = place(false);
        let is_fat64 = total_size > u64::from(u32::MAX);
        if is_fat64 {
            (offsets, total_size) = place(true);
        }
        Layout {
            is_fat64,
            align_bits: align.trailing_zeros(),
            offsets,
            total_size,
        }
    }

    fn header_size(&self) -> usize {
        SIZEOF_FAT_HEADER + self.offsets.len() * fat_arch_size(self.is_fat64)
    }
}

/// Padding between slices; never longer than `MAX_ALIGN`
static ZEROS: [u8; MAX_ALIGN as usize] = [0; MAX_ALIGN as usize];

/// Write every buffer in `bufs`, with as few calls as the writer allows
fn write_all_vectored<W: Write>(writer: &mut W, mut bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
    // drop leading empty buffers
    IoSlice::advance_slices(&mut bufs, 0);
    while !bufs.is_empty() {
        match writer.write_vectored(bufs) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => IoSlice::advance_slices(&mut bufs, n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Mach-O fat binary writer
///
/// Input added with [`FatWriter::add`] can either be borrowed (`&'a [u8]`) or
/// owned (`Vec<u8>`); in both cases it is never copied.
#[derive(Debug, Default)]
pub struct FatWriter<'a> {
    arches: Vec<ThinArch<'a>>,
}

impl<'a> FatWriter<'a> {
    /// Create a new Mach-O fat binary writer
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new thin Mach-O binary, static archive, LLVM bitcode file
    /// or all slices of an existing fat binary.
    ///
    /// Only the file header is parsed, the data is not copied.
    pub fn add<T: Into<Cow<'a, [u8]>>>(&mut self, bytes: T) -> Result<(), Error> {
        self.add_data(bytes.into().into())
    }

    fn add_data(&mut self, data: ArchData<'a>) -> Result<(), Error> {
        let buf = data.as_slice();
        let not_macho = || Error::InvalidMachO("input is not a macho file".to_string());
        let (header, align) = match classify(buf)?.ok_or_else(not_macho)? {
            Kind::Thin(header) => (header, get_align_from_cpu_types(header)),
            Kind::Fat => return self.add_fat(data),
            Kind::Archive => {
                let header = archive_arch(buf)?;
                let align = if header.cpu_type & CPU_ARCH_ABI64 != 0 {
                    8 /* alignof(u64) */
                } else {
                    4 /* alignof(u32) */
                };
                (header, align)
            }
            #[cfg(feature = "bitcode")]
            Kind::Bitcode => (get_arch_from_bitcode(buf)?, 1),
            #[cfg(not(feature = "bitcode"))]
            Kind::Bitcode => {
                return Err(Error::InvalidMachO(
                    "bitcode input is unsupported".to_string(),
                ))
            }
        };
        self.push(data, header, align)
    }

    fn add_fat(&mut self, data: ArchData<'a>) -> Result<(), Error> {
        let buf = data.as_slice();
        let fat = MultiArch::new(buf)?;
        for arch in fat.iter_arches() {
            let arch = arch?;
            let start = arch.offset as usize;
            let end = start
                .checked_add(arch.size as usize)
                .filter(|&end| end <= buf.len())
                .ok_or_else(|| Error::InvalidMachO("fat arch slice out of bounds".to_string()))?;
            self.add_data(data.slice(start..end))?;
        }
        Ok(())
    }

    fn push(&mut self, data: ArchData<'a>, header: MachHeader, align: u64) -> Result<(), Error> {
        // Check if this architecture already exists
        if self
            .arches
            .iter()
            .any(|arch| arch.header.same_arch(header.cpu_type, header.cpu_subtype))
        {
            return Err(Error::DuplicatedArch(header.arch_name().to_string()));
        }
        self.arches.push(ThinArch {
            data,
            header,
            align,
        });
        // Sort the files by alignment to save space in ouput
        self.arches.sort_by(|a, b| {
            if a.header.cpu_type == b.header.cpu_type {
                // if cpu types match, sort by cpu subtype
                return a.header.cpu_subtype.cmp(&b.header.cpu_subtype);
            }
            // force arm64-family to follow after all other slices
            if a.header.cpu_type == CPU_TYPE_ARM64 {
                return Ordering::Greater;
            }
            if b.header.cpu_type == CPU_TYPE_ARM64 {
                return Ordering::Less;
            }
            a.align.cmp(&b.align)
        });
        Ok(())
    }

    /// Remove an architecture, returning its bytes
    ///
    /// The bytes are returned as they were added: borrowed input is returned
    /// borrowed, owned input is returned owned without copying whenever the
    /// allocation isn't shared with another slice of the same fat binary.
    pub fn remove(&mut self, arch: &str) -> Option<Cow<'a, [u8]>> {
        let (cpu_type, cpu_subtype) = get_arch_from_flag(arch)?;
        let index = self
            .arches
            .iter()
            .position(|arch| arch.header.same_arch(cpu_type, cpu_subtype))?;
        Some(self.arches.remove(index).data.into_cow())
    }

    /// Check whether a certain architecture exists in this fat binary
    pub fn exists(&self, arch: &str) -> bool {
        match get_arch_from_flag(arch) {
            Some((cpu_type, cpu_subtype)) => self
                .arches
                .iter()
                .any(|arch| arch.header.same_arch(cpu_type, cpu_subtype)),
            None => false,
        }
    }

    /// Number of architectures in this fat binary
    pub fn len(&self) -> usize {
        self.arches.len()
    }

    /// Whether this fat binary contains no architectures
    pub fn is_empty(&self) -> bool {
        self.arches.is_empty()
    }

    fn layout(&self) -> Layout {
        let sizes: Vec<u64> = self.arches.iter().map(ThinArch::len).collect();
        let align = self.arches.iter().map(|arch| arch.align).max().unwrap_or(1);
        Layout::compute(&sizes, align)
    }

    /// Total size in bytes of the fat binary [`FatWriter::write_to`] produces
    ///
    /// Useful to pre-allocate the output buffer.
    pub fn total_size(&self) -> u64 {
        if self.arches.is_empty() {
            return 0;
        }
        self.layout().total_size
    }

    /// The `fat_header` followed by the `fat_arch` table.
    ///
    /// The fat binary header is big-endian, regardless of the endianness of
    /// the contained files.
    fn header_bytes(&self, layout: &Layout) -> Vec<u8> {
        let mut hdr = Vec::with_capacity(layout.header_size());
        let magic = if layout.is_fat64 {
            FAT_MAGIC_64
        } else {
            FAT_MAGIC
        };
        hdr.extend_from_slice(&magic.to_be_bytes());
        hdr.extend_from_slice(&(self.arches.len() as u32).to_be_bytes());
        for (arch, &arch_offset) in self.arches.iter().zip(&layout.offsets) {
            hdr.extend_from_slice(&arch.header.cpu_type.to_be_bytes());
            hdr.extend_from_slice(&arch.header.cpu_subtype.to_be_bytes());
            if layout.is_fat64 {
                hdr.extend_from_slice(&arch_offset.to_be_bytes());
                hdr.extend_from_slice(&arch.len().to_be_bytes());
                hdr.extend_from_slice(&layout.align_bits.to_be_bytes());
                // Reserved
                hdr.extend_from_slice(&0u32.to_be_bytes());
            } else {
                hdr.extend_from_slice(&(arch_offset as u32).to_be_bytes());
                hdr.extend_from_slice(&(arch.len() as u32).to_be_bytes());
                hdr.extend_from_slice(&layout.align_bits.to_be_bytes());
            }
        }
        debug_assert_eq!(hdr.len(), layout.header_size());
        hdr
    }

    /// Write Mach-O fat binary into the writer
    ///
    /// The header, the padding and every slice go out in a single vectored
    /// write when the writer supports it.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        if self.arches.is_empty() {
            return Ok(());
        }
        let layout = self.layout();
        let hdr = self.header_bytes(&layout);
        // header, then padding + data per arch
        let mut bufs = Vec::with_capacity(1 + 2 * self.arches.len());
        bufs.push(IoSlice::new(&hdr));
        let mut offset = hdr.len() as u64;
        for (arch, &arch_offset) in self.arches.iter().zip(&layout.offsets) {
            let padding = (arch_offset - offset) as usize;
            debug_assert!(padding < ZEROS.len());
            bufs.push(IoSlice::new(&ZEROS[..padding]));
            bufs.push(IoSlice::new(arch.data.as_slice()));
            offset = arch_offset + arch.len();
        }
        write_all_vectored(writer, &mut bufs)?;
        Ok(())
    }

    /// Write Mach-O fat binary to a file
    ///
    /// The file is created or truncated, and made executable (mode `0755`)
    /// like `lipo` does, whether or not it already existed.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let file = File::create(path)?;
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        // Large enough to coalesce the header, the padding and any small
        // slices into one write; big slices bypass the buffer anyway.
        let mut writer = BufWriter::with_capacity(4 * MAX_ALIGN as usize, file);
        self.write_to(&mut writer)?;
        writer.flush()?;
        Ok(())
    }
}

#[cfg(feature = "bitcode")]
fn get_arch_from_bitcode(buffer: &[u8]) -> Result<MachHeader, Error> {
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
            let fields: Vec<u8> = record.fields().iter().map(|x| *x as u8).collect();
            String::from_utf8(fields).ok()
        });
    if let Some(triple) = target_triple {
        if let Some(triple) = triple.split('-').next() {
            let (cpu_type, cpu_subtype) = match triple {
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
            };
            return Ok(MachHeader {
                cpu_type,
                cpu_subtype,
            });
        }
    }
    Err(Error::InvalidMachO("input is not a macho file".to_string()))
}

fn get_align_from_cpu_types(header: MachHeader) -> u64 {
    // `get_arch_name_from_types` matches on the exact (cputype, cpusubtype)
    // pair, so the capability bits must be stripped first or e.g. arm64e
    // (`cpusubtype == 0x80000002`) would not be recognized.
    let cpu_subtype = strip_cpu_subtype_caps(header.cpu_subtype);
    if let Some(arch_name) = get_arch_name_from_types(header.cpu_type, cpu_subtype) {
        if let Some((cpu_type, _)) = get_arch_from_flag(arch_name) {
            match cpu_type {
                // embedded
                CPU_TYPE_ARM | CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => return MAX_ALIGN,
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
    // Unknown architecture: like `lipo`, guess high when unsure. This must
    // never be 0, otherwise offset rounding in `write_to` divides by zero.
    MAX_ALIGN
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fs;

    use goblin::mach::cputype::{CPU_SUBTYPE_ARM64_E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64};

    use super::{FatWriter, Layout};
    use crate::error::Error;
    use crate::read::FatReader;

    /// A writer that refuses vectored writes, to exercise the fallback path
    struct Unvectored(Vec<u8>);

    impl std::io::Write for Unvectored {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // partial writes on purpose
            let n = buf.len().min(7);
            self.0.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_fat_writer_add_exe() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        assert_eq!(out.len() as u64, fat.total_size());

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());

        // same bytes through a writer without vectored I/O
        let mut plain = Unvectored(Vec::new());
        fat.write_to(&mut plain).unwrap();
        assert_eq!(plain.0, out);

        fat.write_to_file("tests/output/fat").unwrap();
        assert_eq!(fs::read("tests/output/fat").unwrap(), out);
    }

    #[cfg(unix)]
    #[test]
    fn test_fat_writer_write_to_file_is_executable() {
        use std::os::unix::fs::PermissionsExt;

        let mut fat = FatWriter::new();
        fat.add(fs::read("tests/fixtures/thin_x86_64").unwrap())
            .unwrap();
        // overwriting a file that isn't executable makes it executable
        let path = "tests/output/fat_perms";
        fs::write(path, b"stale").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        fat.write_to_file(path).unwrap();
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        assert_eq!(fs::read(path).unwrap().len() as u64, fat.total_size());
    }

    #[test]
    fn test_fat_writer_add_borrowed_is_zero_copy() {
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        let mut fat = FatWriter::new();
        fat.add(&f1).unwrap();
        fat.add(f2.as_slice()).unwrap();
        assert_eq!(fat.len(), 2);

        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        let reader = FatReader::new(&out).unwrap();
        assert_eq!(reader.extract("x86_64").unwrap(), f1.as_slice());
        assert_eq!(reader.extract("arm64").unwrap(), f2.as_slice());

        // removed data is handed back borrowed, pointing into the original buffer
        match fat.remove("arm64").unwrap() {
            Cow::Borrowed(data) => assert!(std::ptr::eq(data, f2.as_slice())),
            Cow::Owned(_) => panic!("expected borrowed data"),
        }
        match fat.remove("x86_64").unwrap() {
            Cow::Borrowed(data) => assert!(std::ptr::eq(data, f1.as_slice())),
            Cow::Owned(_) => panic!("expected borrowed data"),
        }
        assert!(fat.is_empty());
        assert_eq!(fat.total_size(), 0);
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_fat_writer_remove_owned() {
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let mut fat = FatWriter::new();
        fat.add(f1.clone()).unwrap();
        match fat.remove("x86_64").unwrap() {
            Cow::Owned(data) => assert_eq!(data, f1),
            Cow::Borrowed(_) => panic!("expected owned data"),
        }
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
    fn test_fat_writer_add_fat_roundtrip() {
        let f1 = fs::read("tests/fixtures/simplefat").unwrap();
        let reader = FatReader::new(&f1).unwrap();
        let x86_64 = reader.extract("x86_64").unwrap();
        let arm64 = reader.extract("arm64").unwrap();

        // owned input: slices share the input allocation
        let mut fat = FatWriter::new();
        fat.add(f1.clone()).unwrap();
        assert_eq!(fat.len(), 2);
        assert_eq!(fat.remove("x86_64").unwrap().as_ref(), x86_64);
        // the last slice standing gets the allocation back without copying
        assert_eq!(fat.remove("arm64").unwrap().as_ref(), arm64);
        assert!(fat.is_empty());

        // borrowed input: slices point into the input
        let mut fat = FatWriter::new();
        fat.add(f1.as_slice()).unwrap();
        match fat.remove("arm64").unwrap() {
            Cow::Borrowed(data) => assert!(std::ptr::eq(data, arm64)),
            Cow::Owned(_) => panic!("expected borrowed data"),
        }

        // written output reproduces the same slices
        let mut fat = FatWriter::new();
        fat.add(&f1).unwrap();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        let reader = FatReader::new(&out).unwrap();
        assert_eq!(reader.extract("x86_64").unwrap(), x86_64);
        assert_eq!(reader.extract("arm64").unwrap(), arm64);
    }

    #[test]
    fn test_fat_writer_add_malformed_fat() {
        let mut f1 = fs::read("tests/fixtures/simplefat").unwrap();
        // first fat_arch.size: make the slice run past the end of the buffer
        f1[8 + 12..8 + 16].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut fat = FatWriter::new();
        assert!(matches!(fat.add(f1), Err(Error::InvalidMachO(_))));

        // nfat_arch far larger than the buffer must error, not allocate
        let mut f1 = fs::read("tests/fixtures/simplefat").unwrap();
        f1[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut fat = FatWriter::new();
        assert!(fat.add(f1).is_err());

        // truncated thin header
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        let mut fat = FatWriter::new();
        assert!(matches!(fat.add(&f2[..16]), Err(Error::InvalidMachO(_))));
        // garbage
        assert!(matches!(
            fat.add(&b"hello"[..]),
            Err(Error::InvalidMachO(_))
        ));
        assert!(matches!(fat.add(&b"\0"[..]), Err(Error::InvalidMachO(_))));
    }

    #[test]
    fn test_fat_writer_add_archive() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64.a").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64.a").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        assert!(fat.exists("x86_64"));
        assert!(fat.exists("arm64"));
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();

        let reader = FatReader::new(&out);
        assert!(reader.is_ok());

        fat.write_to_file("tests/output/fat.a").unwrap();
    }

    /// Build a GNU/SysV style archive (plain and `/` prefixed member names,
    /// symbol table and long name table members) around `objects`.
    fn gnu_archive(objects: &[(&str, &[u8])]) -> Vec<u8> {
        fn member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
            out.extend_from_slice(format!("{:<16}", name).as_bytes());
            out.extend_from_slice(format!("{:<12}", 0).as_bytes());
            out.extend_from_slice(format!("{:<6}", 0).as_bytes());
            out.extend_from_slice(format!("{:<6}", 0).as_bytes());
            out.extend_from_slice(format!("{:<8}", 644).as_bytes());
            out.extend_from_slice(format!("{:<10}", data.len()).as_bytes());
            out.extend_from_slice(b"`\n");
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        let mut out = b"!<arch>\n".to_vec();
        // symbol table: 1 entry, bogus offset, one symbol name
        let mut symtab = 1u32.to_be_bytes().to_vec();
        symtab.extend_from_slice(&0u32.to_be_bytes());
        symtab.extend_from_slice(b"_main\0");
        member(&mut out, "/", &symtab);
        member(&mut out, "//", b"a_very_long_object_file_name.o/\n");
        member(&mut out, "/0", b"not an object");
        for (name, data) in objects {
            member(&mut out, name, data);
        }
        out
    }

    #[test]
    fn test_fat_writer_add_gnu_archive() {
        let x86_64 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let arm64 = fs::read("tests/fixtures/thin_arm64").unwrap();
        let mut fat = FatWriter::new();
        fat.add(gnu_archive(&[("x.o/", &x86_64)])).unwrap();
        fat.add(gnu_archive(&[("odd", &[1u8]), ("a.o/", &arm64)]))
            .unwrap();
        assert!(fat.exists("x86_64"));
        assert!(fat.exists("arm64"));
        assert_eq!(fat.len(), 2);

        let mut fat = FatWriter::new();
        match fat.add(gnu_archive(&[("text.txt/", b"hello")])) {
            Err(Error::InvalidMachO(msg)) => assert!(msg.contains("No Mach-O")),
            other => panic!("expected InvalidMachO error, got {:?}", other),
        }
        // truncated member
        let mut truncated = gnu_archive(&[("x.o/", &x86_64)]);
        truncated.truncate(truncated.len() - 1);
        assert!(matches!(fat.add(truncated), Err(Error::InvalidMachO(_))));
        assert!(matches!(
            fat.add(&b"!<arch>\n"[..]),
            Err(Error::InvalidMachO(_))
        ));
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
    fn test_fat_writer_add_arm64e() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64e").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        assert!(fat.exists("x86_64"));
        assert!(fat.exists("arm64e"));
        assert!(!fat.exists("arm64"));

        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        let reader = FatReader::new(&out).unwrap();
        let arches = reader.arches().unwrap();
        assert_eq!(arches.len(), 2);
        for arch in &arches {
            // arm64 family requires 2^14 alignment, and it's the max of all slices
            assert_eq!(arch.align, 14);
            assert_eq!(arch.offset % 0x4000, 0);
        }
        // capability bits are preserved in the fat_arch header
        let arm64e = arches
            .iter()
            .find(|arch| arch.cputype == CPU_TYPE_ARM64)
            .unwrap();
        assert_eq!(arm64e.cpusubtype & !CPU_SUBTYPE_MASK, CPU_SUBTYPE_ARM64_E);
        assert_ne!(arm64e.cpusubtype & CPU_SUBTYPE_MASK, 0);

        fat.write_to_file("tests/output/fat_arm64e").unwrap();
    }

    #[test]
    fn test_fat_writer_arm64e_only() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_arm64e").unwrap();
        fat.add(f1).unwrap();
        let mut out = Vec::new();
        // used to panic with "attempt to divide by zero"
        fat.write_to(&mut out).unwrap();
        let reader = FatReader::new(&out).unwrap();
        let arches = reader.arches().unwrap();
        assert_eq!(arches.len(), 1);
        assert_eq!(arches[0].align, 14);
        assert_eq!(arches[0].offset, 0x4000);
    }

    #[test]
    fn test_fat_writer_add_duplicated_arm64e() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_arm64e").unwrap();
        fat.add(f1.clone()).unwrap();
        match fat.add(f1) {
            Err(Error::DuplicatedArch(arch)) => assert_eq!(arch, "arm64e"),
            other => panic!("expected DuplicatedArch error, got {:?}", other),
        }
    }

    #[test]
    fn test_fat_writer_remove_arm64e() {
        let mut fat = FatWriter::new();
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64e").unwrap();
        fat.add(f1).unwrap();
        fat.add(f2).unwrap();
        assert!(fat.remove("arm64").is_none());
        assert!(fat.remove("arm64e").is_some());
        assert!(fat.exists("x86_64"));
        assert!(!fat.exists("arm64e"));
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
        // removing the arm64 slice drops the alignment back to x86_64's
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        let reader = FatReader::new(&out).unwrap();
        let arches = reader.arches().unwrap();
        assert_eq!(arches.len(), 1);
        assert_eq!(arches[0].align, 12);
        assert_eq!(arches[0].offset, 0x1000);
    }

    #[test]
    fn test_layout() {
        let layout = Layout::compute(&[100, 0x1000], 0x1000);
        assert!(!layout.is_fat64);
        assert_eq!(layout.align_bits, 12);
        assert_eq!(layout.header_size(), 8 + 2 * 20);
        assert_eq!(layout.offsets, vec![0x1000, 0x2000]);
        assert_eq!(layout.total_size, 0x3000);

        // slices too large for 32-bit offsets switch to a fat64 header
        let layout = Layout::compute(&[1 << 32, 16], 0x4000);
        assert!(layout.is_fat64);
        assert_eq!(layout.align_bits, 14);
        assert_eq!(layout.header_size(), 8 + 2 * 32);
        assert_eq!(layout.offsets, vec![0x4000, 0x4000 + (1 << 32)]);
        assert_eq!(layout.total_size, 0x4000 + (1 << 32) + 16);
    }
}
