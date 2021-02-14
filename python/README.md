# fat-macho

[![GitHub Actions](https://github.com/messense/fat-macho-rs/workflows/Python/badge.svg)](https://github.com/messense/fat-macho-rs/actions?query=workflow%3APython)
[![PyPI](https://img.shields.io/pypi/v/fat-macho.svg)](https://pypi.org/project/fat-macho)

Python wrapper of the [fat-macho](https://github.com/messense/fat-macho-rs) Rust crate.

## Installation

```bash
pip install fat-macho
```

## Usage

### Generate a Mach-O fat binary

```python
from fat_macho import FatWriter


writer = FatWriter()
with open("x86_64_thin_file_path", "rb") as f:
    writer.add(f.read())
with open("arm64_thin_file_path", "rb") as f:
    writer.add(f.read())
# Get Mach-O fat binary as bytes
fat_bytes = writer.generate()
# Write to file
writer.write_to("fat_file_path")
```

## License

This work is released under the MIT license. A copy of the license is provided in the [LICENSE](../LICENSE) file.