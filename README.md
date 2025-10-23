# BinAnalyzer

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Build](https://github.com/Oblivionsage/BinAnalyzer/actions/workflows/c-cpp.yml/badge.svg)

**Modern binary analysis tool for offensive security research and malware analysis.**
```
Cross-platform | Fast | Modular | Open Source
```

---

##  Legal Disclaimer

**For authorized security research and educational purposes only.**

By using this tool, you agree to obtain proper authorization, comply with all laws, and accept full responsibility for your actions. Developers are not liable for misuse. Unauthorized use may result in criminal prosecution.

---

## Overview

BinAnalyzer is a comprehensive binary analysis framework built in modern C++17. It combines static analysis, threat intelligence extraction, and offensive security research capabilities in a single, efficient tool.

**Key Capabilities:**

- Static binary analysis with entropy detection
- Import table threat assessment (100+ suspicious APIs)
- Security mitigation analysis (ASLR, DEP, CFG, SEH)
- Packer detection (UPX, Themida, VMProtect, etc.)
- Shellcode pattern recognition
- Network IOC extraction (IPs, domains, URLs)
- Suspicious string categorization (crypto, anti-VM, persistence)
- PE/ELF format parsing

---

## Quick Start

### Installation

**Prerequisites:** CMake 3.15+, C++17 compiler, OpenSSL
```bash
# Debian/Ubuntu/Kali
sudo apt install build-essential cmake libssl-dev

# macOS
brew install cmake openssl

# Clone and build
git clone https://github.com/Oblivionsage/BinAnalyzer.git
cd BinAnalyzer && mkdir build && cd build
cmake .. && make

# Run
./binanalyzer --help
```

### Basic Usage
```bash
# Standard analysis
./binanalyzer binary.exe

# Red Team mode (full offensive analysis)
./binanalyzer --red-team malware.exe

# Extract strings only
./binanalyzer --strings-only binary.dll

# Custom offset/length
./binanalyzer --offset 0x1000 --length 512 file.bin
```

---

## Features

### Phase 1: Core Analysis (done)

**Hex Viewer**
- Intelligent color-coded byte display
- Configurable offset and length
- ASCII decoding alongside hex

**File Information**
- MD5 and SHA256 hashing
- File size and type detection
- Byte statistics and entropy calculation

**PE Parser**
- Architecture detection (x86/x64)
- Entry point and image base
- Section enumeration
- Compilation timestamp

**String Extraction**
- ASCII string extraction
- Configurable minimum length
- Context-aware filtering

### Phase 2: Offensive Security Analysis (done)

**Import Table Threat Assessment**
- 100+ suspicious API database
- 12 threat categories (Process Injection, Memory Manipulation, Anti-Debug, etc.)
- Severity scoring: INFO → LOW → MEDIUM → HIGH → CRITICAL
- Pattern matching with confidence levels

**Security Mitigations Check**
- ASLR (Address Space Layout Randomization)
- DEP/NX (Data Execution Prevention)
- CFG (Control Flow Guard)
- SEH (Safe Exception Handlers)
- High Entropy ASLR (64-bit)
- Security score calculation (0-100)
- RWX section detection (critical vulnerability indicator)

**Packer Detection**
- Signature-based detection: UPX, Themida, VMProtect, ASPack, PECompact, MPRESS
- Entropy analysis (>7.0 = suspicious)
- Entry point anomaly detection
- Import count heuristics
- Confidence scoring

**Shellcode Pattern Recognition**
- NOP sled detection (20+ consecutive 0x90)
- GetPC techniques (CALL/POP, FNSTENV)
- Egg hunter patterns
- Metasploit encoder stubs
- WinExec signatures

**Network IOC Extraction**
- IPv4 address extraction
- Domain identification (14 TLDs)
- URL parsing (HTTP/HTTPS/FTP)
- Email address validation
- Context extraction for each IOC

**Suspicious String Analysis**
- 60+ keyword database across 10 categories:
  - Cryptography (AES, RC4, XOR)
  - Anti-VM (VMware, VirtualBox, QEMU)
  - Anti-Debug (IsDebuggerPresent, CheckRemoteDebugger)
  - Persistence (Registry Run keys, scheduled tasks)
  - Sandbox Detection (Cuckoo, joe.exe)
  - Reconnaissance (ipconfig, whoami, systeminfo)
  - Lateral Movement (psexec, WMI)
  - Data Exfiltration
  - Malware APIs (CreateRemoteThread, VirtualAllocEx)
  - Debugging Tools (OllyDbg, IDA, x64dbg)
- Suspicion scoring (0.0-1.0)
- Category-based color coding

**Red Team Analysis Mode**

Six-stage comprehensive analysis pipeline:
1. Import Table Analysis
2. Security Mitigations Assessment
3. Packer Detection
4. Shellcode Pattern Scanning
5. Network IOC Extraction
6. Suspicious String Categorization

Final summary with aggregated threat intelligence.

---

## Command-Line Options
```
Usage: binanalyzer [OPTIONS] <file>

Analysis Options:
  --red-team, -r          Enable Red Team analysis mode (6-stage offensive analysis)
  --strings-only          Extract and display strings only

Display Options:
  --offset, -o <hex>      Start hex dump at offset (default: 0x0)
  --length, -l <num>      Number of bytes to display (default: 256)
  --min-string, -m <num>  Minimum string length (default: 5)
  --no-color              Disable colored output

Information:
  --help, -h              Display this help message
  --version, -v           Show version information
```

---

## Roadmap

### Phase 3: Advanced Static Analysis

**Export Table Analysis**
- Exported function enumeration
- Ordinal-based exports
- Forwarded exports detection
- DLL hijacking vulnerability assessment

**Section Analysis**
- Detailed section characteristics
- Virtual vs raw size discrepancies
- Suspicious section names
- Section entropy mapping

**Resource Analysis**
- Icon, dialog, and image extraction
- Hidden executables in resources
- Dropper detection
- Resource language analysis

**TLS Callback Detection**
- Thread Local Storage callback enumeration
- Pre-main execution detection
- Anti-analysis technique identification

**Rich Header Analysis**
- Compiler toolchain detection
- Build environment fingerprinting
- Authenticity verification

**Code Cave Detection**
- Null byte sequence identification
- Injection point enumeration
- Size and location mapping

### Phase 4: Dynamic Capabilities

**Disassembly Engine**
- Capstone integration for x86/x64
- Function boundary detection
- Call graph generation
- Control flow analysis

**API Call Tracing**
- Imported function resolution
- Indirect call detection
- API hooking identification

**Cryptographic Analysis**
- Constant detection (crypto keys, IVs)
- Algorithm identification
- Base64/XOR pattern matching

### Phase 5: Intelligence & Automation

**YARA Integration**
- Custom rule engine
- Malware family identification
- Signature matching
- Rule compilation

**VirusTotal Integration**
- Hash-based lookups
- Behavioral analysis retrieval
- Detection ratio display
- Community comments

**ImpHash Calculation**
- Import hash generation
- Malware family correlation
- Database integration

**Sandbox Integration**
- Cuckoo Sandbox API
- Any.run integration
- Joe Sandbox support

### Phase 6: Interactive Features

**TUI (Text User Interface)**
- ncurses-based interface
- Keyboard navigation
- Split-pane view (hex + disassembly)
- Bookmarks and annotations

**Batch Processing**
- Directory scanning
- Recursive analysis
- Report generation (JSON, XML, HTML)
- Parallel processing

**Plugin System**
- Lua/Python scripting interface
- Custom analyzer plugins
- Output format plugins
- Extensible architecture

### Phase 7: Specialized Formats

**ELF Analysis**
- Full ELF header parsing
- Program header enumeration
- Section header analysis
- Symbol table extraction
- Dynamic linking analysis

**Mach-O Support**
- macOS binary parsing
- Universal binary handling
- Code signing verification

**PE64 Enhancements**
- Exception handler analysis
- Load config directory
- Delay-load imports

**Android APK**
- DEX file parsing
- Manifest analysis
- Native library extraction

### Phase 8: Advanced Threat Detection

**Behavioral Indicators**
- Process hollowing detection
- DLL injection patterns
- Reflective loading signatures
- Heaven's Gate detection (WoW64)

**Evasion Techniques**
- Time-based delays
- Environment checks
- Debugger detection methods
- VM fingerprinting

**Ransomware Indicators**
- File extension targeting
- Encryption routine patterns
- Ransom note strings
- Bitcoin address extraction

**APT Techniques**
- Living-off-the-land binaries (LOLBins)
- Fileless malware indicators
- Command-and-control patterns
- Lateral movement artifacts

---

## Technical Details

**Architecture:** Modular C++17 design with header-only components

**Performance:** Optimized for large files (2MB scan limit, streaming processing)

**Dependencies:** OpenSSL (hashing), standard C++ library

**Platform Support:** Linux (primary), macOS, Windows (via MinGW/MSVC)

**Build System:** CMake 3.15+ with cross-platform configuration

---

## Contributing

**Bug Reports:** Open an issue with reproduction steps and system info

**Feature Requests:** Describe use case and implementation approach

**Pull Requests:** Fork, create feature branch, submit PR with tests

**Code Style:** C++17 standards, meaningful names, documented logic

---

## License

MIT License - see [LICENSE](LICENSE) file

Copyright (c) 2025 Oblivionsage

---

## Acknowledgments

Inspired by: PEiD, Detect It Easy, PEStudio, CFF Explorer, IDA Pro

Built with: OpenSSL (cryptography), modern C++ standard library

Community: Thanks to reverse engineering and infosec communities

---

**GitHub:** [Oblivionsage/BinAnalyzer](https://github.com/Oblivionsage/BinAnalyzer)

**Developer:** [@Oblivionsage](https://github.com/Oblivionsage)
