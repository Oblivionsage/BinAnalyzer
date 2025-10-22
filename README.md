##  BinAnalyzer

A modern terminal-based binary analysis tool written in C++.

## Features

### Phase 1 (In Progress)

- Colorized hex viewer
- File information (size, MD5/SHA256)
- String extraction
- PE header parser (Windows .exe/.dll)


### Phase 2 (Planned)

- ELF header parser (Linux)
- Import/Export tables
- Section/Segment analysis
- Entropy calculation


### Phase 3 (Planned)

- Pattern matching
- Disassembly support
- Graph visualization
- Plugin system

## Installation

### Requirements

- CMake 3.15+
- C++17 compatible compiler (GCC 7+, Clang 5+)
- OpenSSL development libraries

### Debian/Ubuntu

```bash
sudo apt-get install build-essential cmake libssl-dev
```

### Build

```bash
cd BinAnalyzer
mkdir build && cd build
cmake ..
make
```

### Usage

```bash
./binanalyzer <binary_file>
```

## License

MIT License

## Developer

Oblivionsage
