f# BinAnalyzer

<div align="center">

![BinAnalyzer Logo](https://img.shields.io/badge/BinAnalyzer-v1.0-blue?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=c%2B%2B)](https://en.cppreference.com/w/cpp/17)
[![CMake](https://img.shields.io/badge/CMake-3.15+-064F8C?style=for-the-badge&logo=cmake)](https://cmake.org/)

**A modern, terminal-based binary analysis tool for reverse engineers and security researchers**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Roadmap](#roadmap) • [Contributing](#contributing)

</div>

---

## Screenshot

<img width="805" alt="BinAnalyzer in action" src="https://github.com/user-attachments/assets/197eb350-53b7-4687-853e-fc6d53a0fb31" />

---

## Overview

BinAnalyzer is a powerful yet lightweight binary analysis tool written in modern C++17. It provides an intuitive, colorized terminal interface for analyzing executable files, extracting information, and performing initial reconnaissance on unknown binaries.

### Why BinAnalyzer?

- **Beautiful Output**: Intelligent color-coding makes hex analysis easier on the eyes
- **Fast & Lightweight**: Written in C++ for maximum performance
- **Modular Design**: Clean architecture makes it easy to extend
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Open Source**: MIT licensed, contributions welcome

---

## Features

### Phase 1 (Current - v1.0)

#### Colorized Hex Viewer
- Intelligent byte highlighting based on content type
  - **Cyan**: PE/ELF magic bytes and signatures
  - **Green**: Printable ASCII characters
  - **Yellow**: Control characters
  - **Blue**: Extended ASCII
  - **Gray**: NULL bytes
- Professional box-drawing interface
- Configurable display length

#### File Information
- MD5 hash calculation
- SHA256 hash calculation
- File size with human-readable format
- Automatic file type detection (PE/ELF)

#### PE Header Parser
- Architecture detection (x86/x64)
- Subsystem identification (Console/GUI)
- Entry point address
- Image base address
- Section count
- Compilation timestamp

#### String Extraction
- Configurable minimum string length
- Filters printable ASCII strings
- Shows first 20 strings with count of remaining

### Phase 2 (Planned)

- ELF header parser (Linux binaries)
- Import/Export table analysis
- Section/Segment detailed analysis
- Entropy calculation (detect packed/encrypted sections)
- Interactive navigation mode

### Phase 3 (Future)

- Pattern matching (YARA-like rules)
- Disassembly support (Capstone integration)
- Dependency graph visualization
- Plugin system for extensibility

---

## Installation

### Prerequisites

#### Debian/Ubuntu/Kali
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev git
```

#### Fedora/RHEL
```bash
sudo dnf install gcc-c++ cmake openssl-devel git
```

#### macOS
```bash
brew install cmake openssl git
```

### Build from Source
```bash
# Clone the repository
git clone https://github.com/Oblivionsage/BinAnalyzer.git
cd BinAnalyzer

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make

# Optional: Install system-wide
sudo make install
```

### Verify Installation
```bash
./binanalyzer --version
```

---

## Usage

### Basic Usage
```bash
./binanalyzer <binary_file>
```

### Examples

#### Analyze an executable
```bash
./binanalyzer /bin/ls
```

#### Analyze a Windows PE file
```bash
./binanalyzer malware_sample.exe
```

#### Analyze the tool itself
```bash
./binanalyzer ./binanalyzer
```

### Sample Output
```
╔════════════════════════════════════ BinAnalyzer v1.0 ════════════════════════════════════╗
║ File: sample.exe                                     Size: 45,312 bytes (44 KB)          ║
║ MD5:    5d41402abc4b2a76b9719d911017c592                                                  ║
║ SHA256: a98f403a50e46591c5fbc238e778b8093cd6a81ad81b7cb11b6ec6c6b54dcf09                ║
╠═══════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                           ║
║  Offset(h) │ 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F │ Decoded ASCII             ║
║ ───────────┼─────────────────────────────────────────────────┼───────────────────────── ║
║  00000000  │ 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 │ MZ..................      ║
║  00000010  │ B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 │ ........@.......          ║
```

---

## Architecture

### Project Structure
```
BinAnalyzer/
├── include/              # Header files
│   ├── file_handler.hpp    # File I/O operations
│   ├── hash_calculator.hpp # MD5/SHA256 calculation
│   ├── hex_viewer.hpp      # Terminal UI and hex display
│   └── pe_parser.hpp       # PE format parsing
├── src/                  # Implementation files
│   ├── file_handler.cpp
│   ├── hash_calculator.cpp
│   ├── hex_viewer.cpp
│   ├── pe_parser.cpp
│   └── main.cpp           # Entry point
├── tests/                # Test files and samples
├── CMakeLists.txt        # Build configuration
└── README.md
```

### Design Principles

- **Modularity**: Each component is independent and reusable
- **Performance**: Efficient file handling and minimal memory footprint
- **Extensibility**: Easy to add new parsers and analyzers
- **Clean Code**: Following modern C++ best practices

---

## Roadmap

### Version 1.1 (Next Release)
- [ ] ELF header parser
- [ ] Import/Export table viewer
- [ ] Enhanced string extraction (Unicode support)
- [ ] Configuration file support

### Version 1.2
- [ ] Entropy analysis and visualization
- [ ] Section-by-section analysis
- [ ] Batch file processing
- [ ] JSON output format

### Version 2.0
- [ ] Interactive TUI mode
- [ ] Disassembly integration
- [ ] Pattern matching engine
- [ ] Plugin API

See [Issues](https://github.com/Oblivionsage/BinAnalyzer/issues) for detailed feature requests and bug reports.

---

## Contributing

Contributions are welcome! Here's how you can help:

### Reporting Bugs
Open an issue with:
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, compiler version)

### Suggesting Features
Open an issue with:
- Feature description
- Use case and motivation
- Possible implementation approach

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style
- Follow C++17 standards
- Use meaningful variable names
- Comment complex logic
- Add unit tests for new features

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
MIT License - Copyright (c) 2025 Oblivionsage
```

---

## Acknowledgments

- Inspired by tools like `xxd`, `hexdump`, and `objdump`
- Built with [OpenSSL](https://www.openssl.org/) for cryptographic functions
- Thanks to the reverse engineering community for inspiration

---

## Contact & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/Oblivionsage/BinAnalyzer/issues)
- **GitHub Discussions**: [Ask questions or share ideas](https://github.com/Oblivionsage/BinAnalyzer/discussions)
- **Developer**: [@Oblivionsage](https://github.com/Oblivionsage)

---

<div align="center">

**If you find this tool useful, please consider giving it a star**

Made for the reverse engineering community

</div>
