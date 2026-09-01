use std::path::PathBuf;
use std::sync::Arc;

use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

struct ErrorWrapper(fat_macho_rs::Error);

/// Mach-O fat binary writer
#[pyclass(module = "fat_macho")]
struct FatWriter {
    inner: fat_macho_rs::FatWriter<'static>,
}

#[pymethods]
impl FatWriter {
    /// Create a new Mach-O fat binary writer
    #[new]
    fn new() -> Self {
        Self {
            inner: fat_macho_rs::FatWriter::new(),
        }
    }

    /// Add a new thin Mach-O binary, static archive, LLVM bitcode file or
    /// all slices of an existing fat binary.
    ///
    /// `bytes` objects are kept alive and referenced, not copied; other
    /// buffer types are copied.
    fn add(&mut self, data: &Bound<'_, PyAny>) -> PyResult<()> {
        let result = if let Ok(bytes) = data.cast::<PyBytes>() {
            let bytes = PyBackedBytes::from(bytes.clone());
            self.inner.add_shared(Arc::new(bytes))
        } else {
            let data: Vec<u8> = data.extract()?;
            self.inner.add(data)
        };
        result.map_err(ErrorWrapper)?;
        Ok(())
    }

    /// Add a file on disk, only its header is read until the fat binary is
    /// written
    fn add_file(&mut self, path: PathBuf) -> PyResult<()> {
        self.inner.add_file(path).map_err(ErrorWrapper)?;
        Ok(())
    }

    /// Remove an architecture, returning its bytes
    fn remove<'py>(
        &mut self,
        py: Python<'py>,
        arch: &str,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let data = self.inner.remove(arch).map_err(ErrorWrapper)?;
        Ok(data.map(|data| PyBytes::new(py, &data)))
    }

    /// Check whether a certain architecture exists in this fat binary
    fn exists(&self, arch: &str) -> bool {
        self.inner.exists(arch)
    }

    /// Write Mach-O fat binary to a file
    fn write_to(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        py.detach(|| self.inner.write_to_file(path))
            .map_err(ErrorWrapper)?;
        Ok(())
    }

    /// Generate Mach-O fat binary and return bytes
    fn generate<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        // write straight into the `bytes` object
        let size = self.inner.total_size() as usize;
        PyBytes::new_with(py, size, |buf| {
            let mut cursor: &mut [u8] = buf;
            self.inner.write_to(&mut cursor).map_err(ErrorWrapper)?;
            Ok(())
        })
    }
}

impl From<ErrorWrapper> for PyErr {
    fn from(err: ErrorWrapper) -> Self {
        use fat_macho_rs::Error;

        let message = err.0.to_string();
        match err.0 {
            Error::Io(_) => PyOSError::new_err(message),
            Error::Bitcode(_)
            | Error::InvalidMachO(_)
            | Error::DuplicatedArch(_)
            | Error::NotFatBinary => PyValueError::new_err(message),
        }
    }
}

#[pymodule]
fn fat_macho(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<FatWriter>()?;
    Ok(())
}
