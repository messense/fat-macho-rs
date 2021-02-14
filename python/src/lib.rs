use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;

struct ErrorWrapper(fat_macho_rs::Error);

/// Mach-O fat binary writer
#[pyclass]
struct FatWriter {
    inner: fat_macho_rs::FatWriter,
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

    /// Add a new thin Mach-O binary
    fn add(&mut self, data: Vec<u8>) -> PyResult<()> {
        self.inner.add(data).map_err(ErrorWrapper)?;
        Ok(())
    }

    /// Remove an architecture
    fn remove(&mut self, arch: &str) -> Option<Vec<u8>> {
        self.inner.remove(arch)
    }

    /// Check whether a certain architecture exists in this fat binary
    fn exists(&self, arch: &str) -> bool {
        self.inner.exists(arch)
    }

    /// Write Mach-O fat binary to a file
    fn write_to(&self, path: &str) -> PyResult<()> {
        self.inner.write_to_file(path).map_err(ErrorWrapper)?;
        Ok(())
    }

    /// Generate Mach-O fat binary and return bytes
    fn generate(&self) -> PyResult<Vec<u8>> {
        let mut data = Vec::new();
        self.inner.write_to(&mut data).map_err(ErrorWrapper)?;
        Ok(data)
    }
}

impl From<ErrorWrapper> for PyErr {
    fn from(err: ErrorWrapper) -> Self {
        use fat_macho_rs::Error;

        match err.0 {
            Error::Io(e) => PyOSError::new_err(e.to_string()),
            Error::Bitcode(e) => PyValueError::new_err(e.to_string()),
            Error::InvalidMachO(e) => PyValueError::new_err(e.to_string()),
            Error::DuplicatedArch(e) => PyValueError::new_err(e.to_string()),
            Error::Goblin(e) => PyValueError::new_err(e.to_string()),
            Error::NotFatBinary => {
                PyValueError::new_err("input is not a Mach-O fat binary".to_string())
            }
        }
    }
}

#[pymodule]
fn fat_macho(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<FatWriter>()?;
    Ok(())
}
