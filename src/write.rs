// Ported from https://github.com/randall77/makefat/blob/master/makefat.go
use std::{
    borrow::Cow,
    cmp::Ordering,
    fmt,
    fs::File,
    io::{self, BufWriter, IoSlice, Write},
    ops::Range,
    path::Path,
    sync::{Arc, Mutex},
};

#[cfg(feature = "bitcode")]
use llvm_bitcode::{bitcode::BitcodeElement, Bitcode};

use goblin::mach::cputype::{
    get_arch_from_flag, CPU_ARCH_ABI64, CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32,
    CPU_TYPE_HPPA, CPU_TYPE_I386, CPU_TYPE_I860, CPU_TYPE_MC680X0, CPU_TYPE_MC88000,
    CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64, CPU_TYPE_SPARC, CPU_TYPE_X86_64,
};
#[cfg(feature = "bitcode")]
use goblin::mach::cputype::{
    CPU_SUBTYPE_ARM64_32_ALL, CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_E, CPU_SUBTYPE_ARM_V4T,
    CPU_SUBTYPE_ARM_V5TEJ, CPU_SUBTYPE_ARM_V6, CPU_SUBTYPE_ARM_V6M, CPU_SUBTYPE_ARM_V7,
    CPU_SUBTYPE_ARM_V7EM, CPU_SUBTYPE_ARM_V7F, CPU_SUBTYPE_ARM_V7K, CPU_SUBTYPE_ARM_V7M,
    CPU_SUBTYPE_ARM_V7S, CPU_SUBTYPE_I386_ALL, CPU_SUBTYPE_POWERPC_ALL, CPU_SUBTYPE_X86_64_ALL,
    CPU_SUBTYPE_X86_64_H,
};
use goblin::mach::fat::FAT_MAGIC;

use crate::error::Error;
use crate::parse::{
    arch_name, archive_arch, classify, fat_arch_size, file_read_at, invalid, FatArchEntry,
    FatHeader, Kind, MachHeader, Source, FAT_MAGIC_64, HEAD_LEN, SIZEOF_FAT_ARCH_64,
    SIZEOF_FAT_HEADER,
};

/// Largest slice alignment we ever use (the arm64 family's 2^14); the padding
/// between two slices is therefore always smaller than this.
const MAX_ALIGN: u64 = 0x4000;

/// Buffer size for copying file-backed slices through user space
const COPY_BUF_LEN: usize = 1 << 20;

/// Vectored writes stack their buffer list for up to this many arches:
/// the header, then padding and data per arch
const INLINE_BUFS: usize = 1 + 2 * 8;

/// A file added with [`FatWriter::add_file`]
struct FileSource {
    file: File,
    /// Held while the file cursor is in use. Positional reads don't need it;
    /// the kernel copy on Linux does, and `FatWriter::write_to` may run on
    /// several threads at once.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    cursor: Mutex<()>,
}

impl FileSource {
    fn new(file: File) -> Self {
        FileSource {
            file,
            cursor: Mutex::new(()),
        }
    }

    /// Copy `range` into the output file without going through user space.
    ///
    /// `io::copy` uses `copy_file_range(2)` (falling back to `sendfile(2)`)
    /// for `File`-shaped readers only, and those read from the file cursor.
    #[cfg(target_os = "linux")]
    fn kernel_copy(&self, range: Range<u64>, writer: &mut BufWriter<File>) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        use std::sync::PoisonError;
        let _cursor = self.cursor.lock().unwrap_or_else(PoisonError::into_inner);
        let mut reader = &self.file;
        reader.seek(SeekFrom::Start(range.start))?;
        let len = range.end - range.start;
        let copied = io::copy(&mut reader.take(len), writer)?;
        if copied != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}

/// Attach the path to an I/O error, so that the message says which file
fn with_path(err: io::Error, path: &Path) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", path.display(), err))
}

/// Bytes backing one slice of the fat binary.
///
/// Input passed to [`FatWriter::add`] is never copied: borrowed input stays
/// borrowed, owned input is moved into a shared allocation so that all slices
/// of an owned fat binary can point into it. Files added with
/// [`FatWriter::add_file`] stay on disk until the fat binary is written.
enum ArchData<'a> {
    Borrowed(&'a [u8]),
    Owned(Arc<Vec<u8>>, Range<usize>),
    Shared(Arc<dyn AsRef<[u8]> + Send + Sync + 'a>, Range<usize>),
    File(Arc<FileSource>, Range<u64>),
}

impl<'a> ArchData<'a> {
    /// The bytes, if they are in memory
    #[inline]
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            ArchData::Borrowed(data) => Some(data),
            ArchData::Owned(data, range) => Some(&data[range.clone()]),
            ArchData::Shared(data, range) => Some(&(**data).as_ref()[range.clone()]),
            ArchData::File(..) => None,
        }
    }

    /// Sub-slice of `self` without copying
    fn slice(&self, range: Range<u64>) -> Self {
        let sub = |base: &Range<usize>| {
            base.start + range.start as usize..base.start + range.end as usize
        };
        match self {
            ArchData::Borrowed(data) => {
                ArchData::Borrowed(&data[range.start as usize..range.end as usize])
            }
            ArchData::Owned(data, base) => ArchData::Owned(data.clone(), sub(base)),
            ArchData::Shared(data, base) => ArchData::Shared(data.clone(), sub(base)),
            ArchData::File(file, base) => ArchData::File(
                file.clone(),
                base.start + range.start..base.start + range.end,
            ),
        }
    }

    /// All the bytes, read from disk if necessary
    fn read_all(&self) -> io::Result<Cow<'_, [u8]>> {
        match self.bytes() {
            Some(bytes) => Ok(Cow::Borrowed(bytes)),
            None => {
                let mut buf = vec![0; self.len() as usize];
                self.read_exact_at(&mut buf, 0)?;
                Ok(Cow::Owned(buf))
            }
        }
    }

    fn into_cow(self) -> io::Result<Cow<'a, [u8]>> {
        Ok(match self {
            ArchData::Borrowed(data) => Cow::Borrowed(data),
            ArchData::Owned(data, range) => match Arc::try_unwrap(data) {
                // sole owner of the whole buffer: hand it back as is
                Ok(data) if range == (0..data.len()) => Cow::Owned(data),
                Ok(data) => Cow::Owned(data[range].to_vec()),
                Err(data) => Cow::Owned(data[range].to_vec()),
            },
            ArchData::Shared(..) | ArchData::File(..) => Cow::Owned(self.read_all()?.into_owned()),
        })
    }
}

impl Source for ArchData<'_> {
    #[inline]
    fn len(&self) -> u64 {
        match self {
            ArchData::Borrowed(data) => data.len() as u64,
            ArchData::Owned(_, range) | ArchData::Shared(_, range) => range.len() as u64,
            ArchData::File(_, range) => range.end - range.start,
        }
    }

    #[inline]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            ArchData::File(file, range) => {
                let start = range.start + offset.min(range.end - range.start);
                let n = buf.len().min((range.end - start) as usize);
                file_read_at(&file.file, &mut buf[..n], start)
            }
            _ => self.bytes().unwrap().read_at(buf, offset),
        }
    }
}

impl<'a> From<Cow<'a, [u8]>> for ArchData<'a> {
    fn from(data: Cow<'a, [u8]>) -> ArchData<'a> {
        match data {
            Cow::Borrowed(data) => ArchData::Borrowed(data),
            Cow::Owned(data) => {
                let len = data.len();
                ArchData::Owned(Arc::new(data), 0..len)
            }
        }
    }
}

impl fmt::Debug for ArchData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            ArchData::Borrowed(_) => "Borrowed",
            ArchData::Owned(..) => "Owned",
            ArchData::Shared(..) => "Shared",
            ArchData::File(..) => "File",
        };
        write!(f, "{}({} bytes)", kind, self.len())
    }
}

#[derive(Debug)]
struct ThinArch<'a> {
    data: ArchData<'a>,
    header: MachHeader,
    align: u64,
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

/// How file-backed slices get to the output
type FileCopy<'w, W> = &'w mut dyn FnMut(&FileSource, Range<u64>, &mut W) -> io::Result<()>;

/// Buffers in flight for one vectored write
struct Pending<'b, 'a> {
    bufs: &'b mut [IoSlice<'a>],
    len: usize,
}

impl<'b, 'a> Pending<'b, 'a> {
    fn push(&mut self, buf: &'a [u8]) {
        self.bufs[self.len] = IoSlice::new(buf);
        self.len += 1;
    }

    fn flush<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        write_all_vectored(writer, &mut self.bufs[..self.len])?;
        self.len = 0;
        Ok(())
    }
}

/// Copies file-backed slices to the output
#[derive(Default)]
struct FileCopier {
    /// User space bounce buffer, allocated on first use
    buf: Vec<u8>,
}

impl FileCopier {
    /// Copy a file range through the buffer, works with any writer
    fn copy<W: Write>(
        &mut self,
        file: &FileSource,
        range: Range<u64>,
        writer: &mut W,
    ) -> io::Result<()> {
        let want = COPY_BUF_LEN.min((range.end - range.start) as usize);
        if self.buf.len() < want {
            self.buf.resize(want, 0);
        }
        let mut offset = range.start;
        while offset < range.end {
            let n = self.buf.len().min((range.end - offset) as usize);
            match file_read_at(&file.file, &mut self.buf[..n], offset) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    writer.write_all(&self.buf[..n])?;
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Copy a file range into the output file, in the kernel where possible
    fn copy_to_file(
        &mut self,
        file: &FileSource,
        range: Range<u64>,
        writer: &mut BufWriter<File>,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            file.kernel_copy(range, writer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.copy(file, range, writer)
        }
    }
}

/// Mach-O fat binary writer
///
/// Input added with [`FatWriter::add`] can either be borrowed (`&'a [u8]`) or
/// owned (`Vec<u8>`); in both cases it is never copied. Input added with
/// [`FatWriter::add_file`] is read from disk only when the fat binary is
/// written.
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
        self.add_data(bytes.into().into(), true)
    }

    /// Like [`FatWriter::add`], for bytes owned by a shared allocation such as
    /// a memory map or a buffer borrowed from another language runtime.
    ///
    /// The allocation is kept alive by the writer and never copied.
    pub fn add_shared<T: AsRef<[u8]> + Send + Sync + 'a>(
        &mut self,
        bytes: Arc<T>,
    ) -> Result<(), Error> {
        let len = (*bytes).as_ref().len();
        self.add_data(ArchData::Shared(bytes, 0..len), true)
    }

    /// Like [`FatWriter::add`], for a file on disk.
    ///
    /// Only the file header is read now; the contents are copied from the
    /// file when the fat binary is written, so the file must not change in
    /// the meantime.
    pub fn add_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|e| with_path(e, path))?;
        let len = file.metadata().map_err(|e| with_path(e, path))?.len();
        let file = Arc::new(FileSource::new(file));
        self.add_data(ArchData::File(file, 0..len), true)
    }

    fn add_data(&mut self, data: ArchData<'a>, allow_fat: bool) -> Result<(), Error> {
        let mut head_buf = [0u8; HEAD_LEN];
        let head = match data.bytes() {
            Some(bytes) => &bytes[..bytes.len().min(HEAD_LEN)],
            None => {
                let n = data.read_head(&mut head_buf)?;
                &head_buf[..n]
            }
        };
        let kind = classify(head)?.ok_or_else(|| invalid("input is not a macho file"))?;
        let (header, align) = match kind {
            Kind::Thin(header) => (header, get_align_from_cpu_types(header)),
            Kind::Fat { .. } if allow_fat => return self.add_fat(data),
            Kind::Fat { .. } => return Err(invalid("fat binary nested inside a fat binary")),
            Kind::Archive => {
                let header = archive_arch(&data)?;
                let align = if header.cpu_type & CPU_ARCH_ABI64 != 0 {
                    8 /* alignof(u64) */
                } else {
                    4 /* alignof(u32) */
                };
                (header, align)
            }
            #[cfg(feature = "bitcode")]
            Kind::Bitcode => (get_arch_from_bitcode(&data.read_all()?)?, 1),
            #[cfg(not(feature = "bitcode"))]
            Kind::Bitcode => return Err(invalid("bitcode input is unsupported")),
        };
        self.push(data, header, align)
    }

    fn add_fat(&mut self, data: ArchData<'a>) -> Result<(), Error> {
        let len = data.len();
        if len < SIZEOF_FAT_HEADER as u64 {
            return Err(invalid("truncated fat header"));
        }
        let mut head = [0u8; SIZEOF_FAT_HEADER];
        data.read_exact_at(&mut head, 0)?;
        let fat = FatHeader::parse(&head).unwrap();
        if len - (SIZEOF_FAT_HEADER as u64) < fat.arch_table_len() {
            return Err(invalid("fat arch table runs past the end of the input"));
        }
        let mut entry_buf = [0u8; SIZEOF_FAT_ARCH_64];
        for i in 0..fat.narches as usize {
            let start = SIZEOF_FAT_HEADER + i * fat.arch_size();
            let entry = match data.bytes() {
                Some(bytes) => &bytes[start..start + fat.arch_size()],
                None => {
                    let entry = &mut entry_buf[..fat.arch_size()];
                    data.read_exact_at(entry, start as u64)?;
                    entry
                }
            };
            let arch = FatArchEntry::parse(entry, fat.is_fat64).unwrap();
            let range = arch
                .range()
                .filter(|range| range.end <= len)
                .ok_or_else(|| invalid("fat arch slice out of bounds"))?;
            self.add_data(data.slice(range), false)?;
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
    /// Shared and file-backed input is copied; reading a file can fail, hence
    /// the `Result`. `Ok(None)` means there is no such architecture.
    pub fn remove(&mut self, arch: &str) -> Result<Option<Cow<'a, [u8]>>, Error> {
        let Some(index) = self.position(arch) else {
            return Ok(None);
        };
        Ok(Some(self.arches.remove(index).data.into_cow()?))
    }

    /// Check whether a certain architecture exists in this fat binary
    pub fn exists(&self, arch: &str) -> bool {
        self.position(arch).is_some()
    }

    fn position(&self, arch: &str) -> Option<usize> {
        let (cpu_type, cpu_subtype) = get_arch_from_flag(arch)?;
        self.arches
            .iter()
            .position(|arch| arch.header.same_arch(cpu_type, cpu_subtype))
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
        let sizes: Vec<u64> = self.arches.iter().map(|arch| arch.data.len()).collect();
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
            let size = arch.data.len();
            if layout.is_fat64 {
                hdr.extend_from_slice(&arch_offset.to_be_bytes());
                hdr.extend_from_slice(&size.to_be_bytes());
                hdr.extend_from_slice(&layout.align_bits.to_be_bytes());
                // Reserved
                hdr.extend_from_slice(&0u32.to_be_bytes());
            } else {
                hdr.extend_from_slice(&(arch_offset as u32).to_be_bytes());
                hdr.extend_from_slice(&(size as u32).to_be_bytes());
                hdr.extend_from_slice(&layout.align_bits.to_be_bytes());
            }
        }
        debug_assert_eq!(hdr.len(), layout.header_size());
        hdr
    }

    /// Write Mach-O fat binary into the writer
    ///
    /// Everything that is in memory goes out in a single vectored write when
    /// the writer supports it.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let mut copier = FileCopier::default();
        self.write_inner(writer, &mut |file, range, writer| {
            copier.copy(file, range, writer)
        })
    }

    fn write_inner<W: Write>(&self, writer: &mut W, copy: FileCopy<'_, W>) -> Result<(), Error> {
        if self.arches.is_empty() {
            return Ok(());
        }
        let layout = self.layout();
        let hdr = self.header_bytes(&layout);
        let count = 1 + 2 * self.arches.len();
        let mut inline = [IoSlice::new(&[]); INLINE_BUFS];
        let mut heap = Vec::new();
        let bufs: &mut [IoSlice<'_>] = if count <= inline.len() {
            &mut inline[..count]
        } else {
            heap.resize(count, IoSlice::new(&[]));
            &mut heap
        };
        let mut pending = Pending { bufs, len: 0 };
        pending.push(&hdr);
        let mut offset = hdr.len() as u64;
        for (arch, &arch_offset) in self.arches.iter().zip(&layout.offsets) {
            let padding = (arch_offset - offset) as usize;
            debug_assert!(padding < ZEROS.len());
            pending.push(&ZEROS[..padding]);
            match &arch.data {
                ArchData::File(file, range) => {
                    pending.flush(writer)?;
                    copy(file, range.clone(), writer)?;
                }
                data => pending.push(data.bytes().expect("in-memory slice")),
            }
            offset = arch_offset + arch.data.len();
        }
        pending.flush(writer)?;
        Ok(())
    }

    /// Write Mach-O fat binary to a file
    ///
    /// The file is created or truncated, and made executable (mode `0755`)
    /// like `lipo` does, whether or not it already existed.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let path = path.as_ref();
        let file = File::create(path).map_err(|e| with_path(e, path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o755))
                .map_err(|e| with_path(e, path))?;
        }
        // Large enough to coalesce the header, the padding and any small
        // slices into one write; big slices bypass the buffer anyway.
        let mut writer = BufWriter::with_capacity(4 * MAX_ALIGN as usize, file);
        let mut copier = FileCopier::default();
        self.write_inner(&mut writer, &mut |file, range, writer| {
            copier.copy_to_file(file, range, writer)
        })?;
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
                _ => return Err(invalid("input is not a macho file")),
            };
            return Ok(MachHeader {
                cpu_type,
                cpu_subtype,
            });
        }
    }
    Err(invalid("input is not a macho file"))
}

fn get_align_from_cpu_types(header: MachHeader) -> u64 {
    if arch_name(header.cpu_type, header.cpu_subtype).is_some() {
        match header.cpu_type {
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
    // Unknown architecture: like `lipo`, guess high when unsure. This must
    // never be 0, otherwise offset rounding in `write_to` divides by zero.
    MAX_ALIGN
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fs;
    use std::sync::Arc;

    use goblin::mach::cputype::{CPU_SUBTYPE_ARM64_E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64};

    use super::{FatWriter, Layout};
    use crate::error::Error;
    use crate::parse::Source;
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
        match fat.remove("arm64").unwrap().unwrap() {
            Cow::Borrowed(data) => assert!(std::ptr::eq(data, f2.as_slice())),
            Cow::Owned(_) => panic!("expected borrowed data"),
        }
        match fat.remove("x86_64").unwrap().unwrap() {
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
        match fat.remove("x86_64").unwrap().unwrap() {
            Cow::Owned(data) => assert_eq!(data, f1),
            Cow::Borrowed(_) => panic!("expected owned data"),
        }
    }

    #[test]
    fn test_fat_writer_add_shared() {
        let f1 = Arc::new(fs::read("tests/fixtures/thin_x86_64").unwrap());
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        let mut fat = FatWriter::new();
        fat.add_shared(f1.clone()).unwrap();
        fat.add(&f2).unwrap();
        assert_eq!(Arc::strong_count(&f1), 2);
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        let reader = FatReader::new(&out).unwrap();
        assert_eq!(reader.extract("x86_64").unwrap(), f1.as_slice());
        assert_eq!(
            fat.remove("x86_64").unwrap().unwrap().as_ref(),
            f1.as_slice()
        );
        assert_eq!(Arc::strong_count(&f1), 1);

        // a shared fat binary: slices share the allocation
        let simplefat = Arc::new(fs::read("tests/fixtures/simplefat").unwrap());
        let mut fat = FatWriter::new();
        fat.add_shared(simplefat.clone()).unwrap();
        assert_eq!(fat.len(), 2);
        assert_eq!(Arc::strong_count(&simplefat), 3);
        let mut out2 = Vec::new();
        fat.write_to(&mut out2).unwrap();
        let mut fat = FatWriter::new();
        fat.add(simplefat.as_slice()).unwrap();
        let mut out3 = Vec::new();
        fat.write_to(&mut out3).unwrap();
        assert_eq!(out2, out3);
    }

    #[test]
    fn test_fat_writer_add_file() {
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        let mut expected = FatWriter::new();
        expected.add(&f1).unwrap();
        expected.add(&f2).unwrap();
        let mut out = Vec::new();
        expected.write_to(&mut out).unwrap();

        let mut fat = FatWriter::new();
        fat.add_file("tests/fixtures/thin_x86_64").unwrap();
        fat.add_file("tests/fixtures/thin_arm64").unwrap();
        assert_eq!(fat.len(), 2);
        assert_eq!(fat.total_size(), expected.total_size());
        let mut out2 = Vec::new();
        fat.write_to(&mut out2).unwrap();
        assert_eq!(out2, out);
        let mut plain = Unvectored(Vec::new());
        fat.write_to(&mut plain).unwrap();
        assert_eq!(plain.0, out);
        fat.write_to_file("tests/output/fat_from_files").unwrap();
        assert_eq!(fs::read("tests/output/fat_from_files").unwrap(), out);

        // removing hands back a copy of the file contents
        match fat.remove("arm64").unwrap().unwrap() {
            Cow::Owned(data) => assert_eq!(data, f2),
            Cow::Borrowed(_) => panic!("expected owned data"),
        }
        assert!(fat.remove("arm64").unwrap().is_none());

        // fat, archive and bitcode files work too
        let mut fat = FatWriter::new();
        fat.add_file("tests/fixtures/simplefat").unwrap();
        assert!(fat.exists("x86_64"));
        assert!(fat.exists("arm64"));
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        let mut expected = FatWriter::new();
        expected
            .add(fs::read("tests/fixtures/simplefat").unwrap())
            .unwrap();
        let mut out2 = Vec::new();
        expected.write_to(&mut out2).unwrap();
        assert_eq!(out, out2);

        let mut fat = FatWriter::new();
        fat.add_file("tests/fixtures/thin_x86_64.a").unwrap();
        fat.add_file("tests/fixtures/thin_arm64.a").unwrap();
        assert_eq!(fat.len(), 2);
        #[cfg(feature = "bitcode")]
        {
            let mut fat = FatWriter::new();
            fat.add_file("tests/fixtures/thin_x86_64.bc").unwrap();
            assert!(fat.exists("x86_64"));
        }

        let mut fat = FatWriter::new();
        match fat.add_file("tests/fixtures/nope") {
            Err(Error::Io(err)) => assert!(err.to_string().contains("tests/fixtures/nope")),
            other => panic!("expected Io error, got {:?}", other),
        }
        assert!(matches!(
            fat.add_file("Cargo.toml"),
            Err(Error::InvalidMachO(_))
        ));
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
        assert_eq!(fat.remove("x86_64").unwrap().unwrap().as_ref(), x86_64);
        // the last slice standing gets the allocation back without copying
        assert_eq!(fat.remove("arm64").unwrap().unwrap().as_ref(), arm64);
        assert!(fat.is_empty());

        // borrowed input: slices point into the input
        let mut fat = FatWriter::new();
        fat.add(f1.as_slice()).unwrap();
        match fat.remove("arm64").unwrap().unwrap() {
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
    fn test_fat_writer_fat64_roundtrip() {
        // a fat64 header is accepted as input like a fat32 one
        let f1 = fs::read("tests/fixtures/thin_x86_64").unwrap();
        let f2 = fs::read("tests/fixtures/thin_arm64").unwrap();
        let mut fat = FatWriter::new();
        fat.add(&f1).unwrap();
        fat.add(&f2).unwrap();
        let layout = fat.layout();
        let mut out = Vec::new();
        fat.write_to(&mut out).unwrap();
        let mut fat64 = Vec::new();
        fat64.extend_from_slice(&super::FAT_MAGIC_64.to_be_bytes());
        fat64.extend_from_slice(&2u32.to_be_bytes());
        for (arch, &offset) in fat.arches.iter().zip(&layout.offsets) {
            fat64.extend_from_slice(&arch.header.cpu_type.to_be_bytes());
            fat64.extend_from_slice(&arch.header.cpu_subtype.to_be_bytes());
            fat64.extend_from_slice(&offset.to_be_bytes());
            fat64.extend_from_slice(&arch.data.len().to_be_bytes());
            fat64.extend_from_slice(&layout.align_bits.to_be_bytes());
            fat64.extend_from_slice(&0u32.to_be_bytes());
        }
        fat64.extend_from_slice(&out[fat64.len()..]);
        let mut fat = FatWriter::new();
        fat.add(&fat64).unwrap();
        let mut out2 = Vec::new();
        fat.write_to(&mut out2).unwrap();
        assert_eq!(out2, out);
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
        assert!(matches!(fat.add(f1), Err(Error::InvalidMachO(_))));

        // a slice pointing back at the fat header must not recurse forever
        let mut f1 = fs::read("tests/fixtures/simplefat").unwrap();
        let len = f1.len() as u32;
        f1[8 + 8..8 + 12].copy_from_slice(&0u32.to_be_bytes());
        f1[8 + 12..8 + 16].copy_from_slice(&len.to_be_bytes());
        let mut fat = FatWriter::new();
        assert!(matches!(fat.add(f1), Err(Error::InvalidMachO(_))));

        // truncated fat header
        let f1 = fs::read("tests/fixtures/simplefat").unwrap();
        let mut fat = FatWriter::new();
        assert!(matches!(fat.add(&f1[..6]), Err(Error::InvalidMachO(_))));

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
        assert!(matches!(fat.add(&b""[..]), Err(Error::InvalidMachO(_))));
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
        // truncated member header
        let mut truncated = gnu_archive(&[]);
        truncated.truncate(8 + 30);
        assert!(matches!(fat.add(truncated), Err(Error::InvalidMachO(_))));
        // bad size field / bad end-of-header marker
        let mut bad = gnu_archive(&[("x.o/", &x86_64)]);
        bad[8 + 48] = b'x';
        assert!(matches!(fat.add(bad), Err(Error::InvalidMachO(_))));
        let mut bad = gnu_archive(&[("x.o/", &x86_64)]);
        bad[8 + 58] = b'x';
        assert!(matches!(fat.add(bad), Err(Error::InvalidMachO(_))));
        assert!(matches!(
            fat.add(&b"!<arch>\n"[..]),
            Err(Error::InvalidMachO(_))
        ));
    }

    #[test]
    fn test_fat_writer_add_bsd_archive_long_names() {
        // the fixtures use BSD `#1/N` names, check the name length is honored
        let f1 = fs::read("tests/fixtures/thin_x86_64.a").unwrap();
        assert!(f1[8..].starts_with(b"#1/"));
        // a member whose `#1/N` claims a name longer than the member
        let mut bad = f1.clone();
        bad[8 + 3..8 + 13].copy_from_slice(b"9999999   ");
        let mut fat = FatWriter::new();
        assert!(matches!(fat.add(bad), Err(Error::InvalidMachO(_))));
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
        assert!(reader.extract("arm64").is_none());
        assert!(reader.extract("arm64e").is_some());

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
        assert!(fat.remove("arm64").unwrap().is_none());
        assert!(fat.remove("not-an-arch").unwrap().is_none());
        assert!(fat.remove("arm64e").unwrap().is_some());
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
        let arm64 = fat.remove("arm64").unwrap();
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
