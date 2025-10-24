# BinAnalyzer

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Build](https://github.com/Oblivionsage/BinAnalyzer/actions/workflows/c-cpp.yml/badge.svg)

Binary analysis toolkit for offensive security research
```
Cross-platform | Fast | Modular | Open Source
```

## Features

- **Multi-Architecture Disassembly** - x86/x64, ARM/ARM64, ARM Thumb with Capstone
- **Auto-Detection** - Automatic architecture and entry point detection (PE/ELF/Mach-O)
- PE/ELF/Mach-O file analysis with entry point detection
- Import table analysis with threat categorization
- Security feature detection (ASLR, DEP, CFG, SafeSEH)
- Packer detection (UPX, Themida, VMProtect, ASPack, etc.)
- Shellcode pattern recognition
- Network IOC extraction (IPs, domains, URLs, emails)
- Suspicious string analysis
- Entropy calculation and byte statistics
- Code cave detection
- Hex dump with colored output

## Installation
```bash
git clone https://github.com/Oblivionsage/BinAnalyzer.git
cd BinAnalyzer
mkdir build && cd build
cmake ..
make
```

**Requirements:**

- C++17 compiler
- CMake 3.15+
- OpenSSL development libraries
- Capstone disassembly library

## Usage
```bash
# Standard analysis with quick disassembly preview
./binanalyzer <file>

# Detailed disassembly from entry point
./binanalyzer --disasm <file>

# Disassemble with specific architecture
./binanalyzer --disasm --arch arm64 firmware.bin
./binanalyzer --disasm --arch thumb binary.elf

# Disassemble 100 instructions from specific offset
./binanalyzer --disasm 100 --offset 0x1000 <file>

# Red team analysis mode
./binanalyzer --red-team <file>

# Extract strings only
./binanalyzer --strings-only <file>

# Hex dump with custom offset/length
./binanalyzer --offset 0x1000 --length 512 <file>

# Test x86-64 (Linux)
./binanalyzer --disasm /bin/ls

# Test PE (Windows)
./binanalyzer --disasm putty.exe

# Test ARM
./binanalyzer --disasm test-arm

# Test Thumb mode
./binanalyzer --disasm --arch thumb --offset 0x8880 binary.elf

# Test ARM64
./binanalyzer --disasm --arch arm64 ios-binary
```

## Output

Minimal terminal output with colored hex addresses, instruction highlighting, and threat indicators.

**Disassembly color scheme:**
- Red: Function calls (`call`, `bl`, `blx`)
- Yellow: Jumps (`je`, `jne`, `jmp`, `b`)
- Blue: SIMD operations (`xmm`, `ymm`, NEON)
- Magenta: System calls (`syscall`, `int`, `svc`)
- Gray: Standard instructions

## Architecture
```
src/
├── main.cpp                  # Entry point
├── file_handler.cpp          # File I/O operations
├── pe_parser.cpp             # PE format parsing
├── disassembler.cpp          # Multi-arch disassembly engine
├── import_analyzer.cpp       # Import table analysis
├── security_analyzer.cpp     # Security features detection
├── packer_detector.cpp       # Packer identification
├── shellcode_detector.cpp    # Shellcode pattern matching
├── ioc_extractor.cpp         # Network IOC extraction
├── string_analyzer.cpp       # Suspicious string detection
└── advanced_analyzer.cpp     # Analysis orchestrator
```


## Roadmap

### Phase 1: Advanced Binary Analysis
- [x] **Disassembly Engine Integration**
  - [x] x86/x64 instruction disassembly
  - [x] Auto-detect entry point (PE/ELF/Mach-O)
  - [x] Architecture detection (32/64-bit)
  - [x] ARM/ARM64/Thumb support
  - [ ] Control flow graph generation
  - [ ] Basic block identification
  - [ ] Function boundary detection
  - [ ] Cross-reference analysis

- [ ] **Advanced Packer Detection**
  - Custom packer signatures database
  - Polymorphic packer detection
  - Runtime packer identification
  - Entropy-based packing analysis
  - Section characteristic analysis
  - Import reconstruction for packed files

- [ ] **Anti-Analysis Technique Detection**
  - Anti-debugging techniques (hardware breakpoints, timing checks, exception handlers)
  - Anti-VM detection (CPUID checks, registry keys, process artifacts)
  - Anti-sandbox techniques (sleep acceleration, mouse/keyboard checks)
  - Environment fingerprinting detection
  - Code obfuscation identification (control flow flattening, opaque predicates)

### Phase 2: Malware Analysis Capabilities
- [ ] **Behavioral Indicators**
  - API call sequence analysis
  - Suspicious API combination detection
  - Thread injection technique identification
  - Process hollowing pattern detection
  - Reflective DLL loading indicators
  - Hook detection capabilities

- [ ] **Cryptography Analysis**
  - Crypto constant detection (AES S-boxes, DES P-boxes, RSA exponents)
  - Custom encryption algorithm identification
  - Key schedule detection
  - Cipher mode identification
  - Hash function constant detection

- [ ] **String Analysis Enhancement**
  - Unicode string extraction
  - Base64/Base32 encoded string detection
  - XOR-encoded string decryption attempts
  - Stack string reconstruction
  - Encrypted string identification

### Phase 3: Exploit Development Support
- [ ] **ROP Gadget Finder**
  - Comprehensive ROP chain search
  - JOP gadget identification
  - Syscall gadget finder
  - Bad character filtering
  - Gadget quality scoring
  - Automatic ROP chain generation

- [ ] **Vulnerability Pattern Detection**
  - Stack buffer overflow indicators
  - Integer overflow patterns
  - Format string vulnerability detection
  - Use-after-free pattern identification
  - Race condition indicators
  - Memory corruption patterns

- [ ] **Exploit Mitigation Bypass**
  - ASLR bypass technique identification
  - DEP bypass gadget search
  - CFG bypass pattern detection
  - Stack canary bypass opportunities
  - SEH overwrite chain analysis

### Phase 4: Advanced Code Analysis
- [ ] **Static Code Analysis**
  - Taint analysis implementation
  - Data flow analysis
  - Use-def chain analysis
  - Reaching definition analysis
  - Live variable analysis
  - Constant propagation

- [ ] **Symbolic Execution**
  - Path constraint collection
  - SMT solver integration (Z3)
  - Automated test case generation
  - Branch coverage analysis
  - Concolic execution support

- [ ] **Binary Diffing**
  - Function-level binary comparison
  - Basic block similarity analysis
  - Patch analysis automation
  - Security update impact assessment
  - 1-day exploit development support

### Phase 5: Network & Communication Analysis
- [ ] **Network Protocol Analysis**
  - C2 protocol pattern detection
  - Custom protocol identification
  - Domain generation algorithm (DGA) detection
  - Beacon interval analysis
  - Encrypted channel identification

- [ ] **Hardcoded Credentials**
  - API key detection
  - Database connection string extraction
  - Authentication token identification
  - Private key detection
  - Certificate extraction

### Phase 6: Sandbox & Dynamic Analysis Integration
- [ ] **Dynamic Analysis Preparation**
  - Automated unpacking preparation
  - Dynamic library dependency resolution
  - Environment setup suggestions
  - Monitoring point identification
  - Breakpoint recommendation

- [ ] **Emulation Support**
  - CPU emulation (Unicorn integration)
  - API emulation for common functions
  - Partial execution support
  - State snapshotting
  - Memory dumping capabilities

### Phase 7: Threat Intelligence Integration
- [ ] **Hash Database Integration**
  - VirusTotal API integration
  - MalwareBazaar lookup
  - Hybrid Analysis submission
  - YARA rule scanning
  - Custom hash database support

- [ ] **IOC Enrichment**
  - IP/Domain reputation lookup
  - ASN information retrieval
  - Geolocation data
  - Historical DNS records
  - WHOIS information

- [ ] **Signature Generation**
  - YARA rule auto-generation
  - Snort/Suricata signature creation
  - ClamAV signature generation
  - Custom signature format support

### Phase 8: Forensics & Investigation
- [ ] **Timeline Analysis**
  - PE timestamp verification
  - Certificate validity period analysis
  - Compilation time extraction
  - Resource timestamp analysis

- [ ] **Attribution Indicators**
  - PDB path extraction and analysis
  - Compiler signature detection
  - Programming language identification
  - Framework/library detection
  - Code reuse analysis

- [ ] **Memory Forensics**
  - Memory dump analysis
  - Process injection artifact detection
  - Heap/stack analysis
  - Malicious driver detection

### Phase 9: Automated Exploit Generation
- [ ] **Fuzzing Integration**
  - Input generation for target analysis
  - Crash triage automation
  - Exploitability assessment
  - AFL/LibFuzzer integration
  - Coverage-guided fuzzing support

- [ ] **Automatic Exploit Development**
  - Vulnerability to exploit automation
  - Shellcode generation
  - Exploit reliability improvement
  - Exploit chain construction
  - Target-specific payload generation

### Phase 10: Reporting & Visualization
- [ ] **Report Generation**
  - PDF report generation
  - HTML interactive reports
  - JSON output for automation
  - Markdown documentation
  - Executive summary generation

- [ ] **Visual Analysis**
  - Control flow graph visualization
  - Call graph generation
  - Import/export dependency graphs
  - Entropy visualization
  - Memory layout visualization

### Phase 11: Platform Extensions
- [ ] **Mobile Binary Analysis**
  - Android APK analysis (DEX, native libraries)
  - iOS binary analysis (Mach-O format)
  - Mobile malware detection
  - Mobile packer detection

- [ ] **Firmware Analysis**
  - Firmware unpacking
  - Embedded system binary analysis
  - IoT device firmware analysis
  - Bootloader analysis

- [ ] **Scripting Language Analysis**
  - PowerShell script analysis
  - Python bytecode analysis
  - JavaScript/VBScript detection
  - Macro analysis (Office documents)

### Phase 12: Machine Learning Integration
- [ ] **ML-Based Detection**
  - Malware family classification
  - Packer identification using ML
  - Anomaly detection
  - Behavioral clustering
  - Zero-day malware detection

- [ ] **Neural Network Analysis**
  - Deep learning-based code analysis
  - Automatic feature extraction
  - Similarity learning
  - Adversarial sample detection

### Phase 13: Collaboration & Automation
- [ ] **API & CLI Enhancement**
  - RESTful API server
  - Batch processing support
  - CI/CD integration
  - Docker containerization
  - Distributed analysis support

- [ ] **Plugin System**
  - Custom analyzer plugins
  - Third-party tool integration
  - Signature database plugins
  - Output format plugins

### Phase 14: Advanced Stealth Analysis
- [ ] **Rootkit Detection**
  - SSDT hook detection
  - IDT/GDT modification detection
  - Hidden process/driver detection
  - Kernel object manipulation detection

- [ ] **Bootkit Analysis**
  - MBR/VBR analysis
  - UEFI firmware analysis
  - Secure boot bypass detection
  - Boot sector analysis

### Phase 15: Exploit Kit Analysis
- [ ] **Exploit Kit Detection**
  - Landing page analysis
  - Exploit payload extraction
  - Shellcode decode automation
  - Drive-by download chain analysis
  - Browser exploit detection

## Contributing

Security researchers and offensive tool developers welcome.

## License

MIT License

## Disclaimer

For authorized security research and penetration testing only. Users are responsible for compliance with applicable laws.

## Author

Oblivionsage
