#include <iostream>
#include <iomanip>
#include <cmath>
#include "file_handler.hpp"
#include "hex_viewer.hpp"
#include "hash_calculator.hpp"
#include "pe_parser.hpp"
#include "cli_parser.hpp"
#include "import_analyzer.hpp"
#include "security_analyzer.hpp"
#include "advanced_analyzer.hpp"
#include "disassembler.hpp"

void displayBanner() {
    std::cout << "\n";
    std::cout << "BinAnalyzer v1.0 - Binary Analysis Tool\n";
    std::cout << "========================================\n\n";
}

BinAnalyzer::Architecture detectArchitecture(const std::vector<uint8_t>& data, size_t& entryPoint) {
    // Check PE file
    if (data.size() >= 0x200 && data[0] == 0x4D && data[1] == 0x5A) {
        uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
        if (peOffset + 0x100 < data.size()) {
            if (data[peOffset] == 'P' && data[peOffset + 1] == 'E') {
                uint16_t machine = *reinterpret_cast<const uint16_t*>(&data[peOffset + 4]);
                uint32_t entryRVA = *reinterpret_cast<const uint32_t*>(&data[peOffset + 40]);
                entryPoint = entryRVA;
                
                // PE machine types
                switch (machine) {
                    case 0x014c: return BinAnalyzer::Architecture::X86_32;  // IMAGE_FILE_MACHINE_I386
                    case 0x8664: return BinAnalyzer::Architecture::X86_64;  // IMAGE_FILE_MACHINE_AMD64
                    case 0x01c0: return BinAnalyzer::Architecture::ARM_32;  // IMAGE_FILE_MACHINE_ARM
                    case 0xaa64: return BinAnalyzer::Architecture::ARM_64;  // IMAGE_FILE_MACHINE_ARM64
                    case 0x01c2: return BinAnalyzer::Architecture::THUMB;   // IMAGE_FILE_MACHINE_THUMB
                }
            }
        }
    }
    // Check ELF file
    else if (data.size() >= 64 && data[0] == 0x7F && data[1] == 0x45) {
        uint8_t elfClass = data[4];  // 1=32-bit, 2=64-bit
        uint16_t machine = 0;
        
        if (elfClass == 2 && data.size() >= 0x40) {
            // ELF64
            machine = *reinterpret_cast<const uint16_t*>(&data[0x12]);
            uint64_t entry = *reinterpret_cast<const uint64_t*>(&data[0x18]);
            if (entry < 0x1000000) {
                entryPoint = static_cast<size_t>(entry);
            }
        } else if (elfClass == 1 && data.size() >= 0x28) {
            // ELF32
            machine = *reinterpret_cast<const uint16_t*>(&data[0x12]);
            uint32_t entry = *reinterpret_cast<const uint32_t*>(&data[0x18]);
            if (entry < 0x1000000) {
                entryPoint = static_cast<size_t>(entry);
            }
        }
        
        // ELF machine types
        switch (machine) {
            case 0x03:   return BinAnalyzer::Architecture::X86_32;  // EM_386
            case 0x3E:   return BinAnalyzer::Architecture::X86_64;  // EM_X86_64
            case 0x28:   return BinAnalyzer::Architecture::ARM_32;  // EM_ARM
            case 0xB7:   return BinAnalyzer::Architecture::ARM_64;  // EM_AARCH64
        }
    }
    // Check Mach-O (iOS/macOS)
    else if (data.size() >= 32) {
        uint32_t magic = *reinterpret_cast<const uint32_t*>(&data[0]);
        
        if (magic == 0xfeedface || magic == 0xcefaedfe) {
            // Mach-O 32-bit
            uint32_t cputype = *reinterpret_cast<const uint32_t*>(&data[4]);
            if (cputype == 12) return BinAnalyzer::Architecture::ARM_32;  // CPU_TYPE_ARM
            if (cputype == 7)  return BinAnalyzer::Architecture::X86_32;
        } else if (magic == 0xfeedfacf || magic == 0xcffaedfe) {
            // Mach-O 64-bit
            uint32_t cputype = *reinterpret_cast<const uint32_t*>(&data[4]);
            if (cputype == 0x0100000c) return BinAnalyzer::Architecture::ARM_64;  // CPU_TYPE_ARM64
            if (cputype == 0x01000007) return BinAnalyzer::Architecture::X86_64;
        }
    }
    
    return BinAnalyzer::Architecture::X86_64;  // Default
}

void displayDisassembly(const std::vector<uint8_t>& data, size_t offset, size_t count, BinAnalyzer::Architecture arch) {
    std::cout << "[*] Disassembly\n";
    std::cout << "---------------\n";
    
    if (offset >= data.size()) {
        std::cout << "Error: Offset exceeds file size\n";
        return;
    }
    
    size_t maxSize = std::min(data.size() - offset, static_cast<size_t>(4096));
    const uint8_t* code = data.data() + offset;
    
    BinAnalyzer::Disassembler disasm(arch);
    auto instructions = disasm.disassemble(code, maxSize, offset);
    
    if (instructions.empty()) {
        std::cout << "Failed to disassemble code\n";
        return;
    }
    
    std::cout << "\nAddress   | Bytes                    | Instruction\n";
    std::cout << "----------+--------------------------+---------------------\n";
    
    size_t displayCount = std::min(instructions.size(), count);
    
    for (size_t i = 0; i < displayCount; i++) {
        const auto& inst = instructions[i];
        
        std::cout << "\033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                  << inst.address << "\033[0m | ";
        
        for (size_t j = 0; j < inst.size && j < 8; j++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(inst.bytes[j]) << " ";
        }
        
        for (size_t j = inst.size; j < 8; j++) {
            std::cout << "   ";
        }
        
        std::cout << "| ";
        std::cout << "\033[93m" << inst.mnemonic << "\033[0m";
        
        if (!inst.operands.empty()) {
            std::cout << " \033[92m" << inst.operands << "\033[0m";
        }
        
        std::cout << "\n" << std::dec;
    }
    
    std::cout << "\nDisassembled " << displayCount << " instructions\n\n";
}

void displayQuickDisassembly(const std::vector<uint8_t>& data, size_t offset, BinAnalyzer::Architecture arch) {
    if (offset >= data.size()) {
        return;
    }
    
    std::cout << "[*] Entry Point Disassembly\n";
    std::cout << "---------------------------\n";
    
    size_t maxSize = std::min(data.size() - offset, static_cast<size_t>(2048));
    const uint8_t* code = data.data() + offset;
    
    BinAnalyzer::Disassembler disasm(arch);
    auto instructions = disasm.disassemble(code, maxSize, offset);
    
    if (instructions.empty()) {
        std::cout << "Unable to disassemble entry point\n\n";
        return;
    }
    
    size_t displayCount = std::min(instructions.size(), static_cast<size_t>(20));
    
    int calls = 0, jumps = 0, simd = 0;
    
    for (size_t i = 0; i < displayCount; i++) {
        const auto& inst = instructions[i];
        
        bool isCall = (inst.mnemonic == "call" || inst.mnemonic == "bl" || inst.mnemonic == "blx");
        bool isJump = (inst.mnemonic[0] == 'j' && inst.mnemonic != "jmp") || 
                      (inst.mnemonic[0] == 'b' && inst.mnemonic != "bl" && inst.mnemonic != "blx");
        bool isJmp = (inst.mnemonic == "jmp" || inst.mnemonic == "b");
        bool isSIMD = (inst.operands.find("xmm") != std::string::npos || 
                       inst.operands.find("ymm") != std::string::npos ||
                       inst.mnemonic[0] == 'v');  // ARM NEON (vmov, vadd, etc)
        bool isSyscall = (inst.mnemonic == "syscall" || inst.mnemonic == "int" || inst.mnemonic == "svc");
        
        if (isCall) calls++;
        if (isJump || isJmp) jumps++;
        if (isSIMD) simd++;
        
        std::cout << "\033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                  << inst.address << "\033[0m  ";
        
        if (isCall) {
            std::cout << "\033[1;91m" << inst.mnemonic << "\033[0m";
        } else if (isSyscall) {
            std::cout << "\033[1;95m" << inst.mnemonic << "\033[0m";
        } else if (isJump || isJmp) {
            std::cout << "\033[1;93m" << inst.mnemonic << "\033[0m";
        } else if (isSIMD) {
            std::cout << "\033[1;94m" << inst.mnemonic << "\033[0m";
        } else {
            std::cout << "\033[90m" << inst.mnemonic << "\033[0m";
        }
        
        if (!inst.operands.empty()) {
            std::cout << " \033[92m" << inst.operands << "\033[0m";
        }
        
        std::cout << "\n" << std::dec;
    }
    
    std::cout << "\n\033[90m[Summary: " << calls << " calls, " << jumps << " jumps";
    if (simd > 0) std::cout << ", " << simd << " SIMD ops";
    std::cout << "]\033[0m\n";
    std::cout << "\033[90mUse --disasm for detailed analysis\033[0m\n\n";
}

void displayBasicInfo(const std::vector<uint8_t>& data, const std::string& filepath) {
    std::cout << "[*] File Analysis\n";
    std::cout << "-----------------\n";
    std::cout << "File: " << filepath << "\n";
    std::cout << "Size: " << data.size() << " bytes (" 
              << std::fixed << std::setprecision(2) 
              << (data.size() / 1024.0) << " KB)\n";
    
    HashCalculator hashCalc;
    std::string md5 = hashCalc.calculateMD5(data);
    std::string sha256 = hashCalc.calculateSHA256(data);
    std::cout << "MD5:    " << md5 << "\n";
    std::cout << "SHA256: " << sha256 << "\n";
    
    bool isPE = false;
    if (data.size() >= 2) {
        if (data[0] == 0x4D && data[1] == 0x5A) {
            std::cout << "Type: \033[93mPE (Windows Executable)\033[0m\n";
            isPE = true;
        } else if (data[0] == 0x7F && data[1] == 0x45) {
            std::cout << "Type: ELF (Linux Binary)\n";
        } else if (data.size() >= 4) {
            uint32_t magic = *reinterpret_cast<const uint32_t*>(&data[0]);
            if (magic == 0xfeedface || magic == 0xcefaedfe || 
                magic == 0xfeedfacf || magic == 0xcffaedfe) {
                std::cout << "Type: \033[92mMach-O (macOS/iOS Binary)\033[0m\n";
            } else {
                std::cout << "Type: Unknown\n";
            }
        } else {
            std::cout << "Type: Unknown\n";
        }
    }
    
    std::cout << "\n[*] Byte Statistics\n";
    std::cout << "-------------------\n";
    
    size_t nullBytes = 0, printable = 0, control = 0, extended = 0;
    int byteCounts[256] = {0};
    
    size_t sampleSize = std::min(data.size(), static_cast<size_t>(1024 * 1024));
    for (size_t i = 0; i < sampleSize; i++) {
        uint8_t byte = data[i];
        byteCounts[byte]++;
        
        if (byte == 0x00) nullBytes++;
        else if (byte >= 0x20 && byte <= 0x7E) printable++;
        else if (byte < 0x20) control++;
        else extended++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / sampleSize;
            entropy -= p * log2(p);
        }
    }
    
    std::cout << "NULL bytes:      " << std::fixed << std::setprecision(2) 
              << (nullBytes * 100.0 / sampleSize) << "%\n";
    std::cout << "Printable ASCII: " << (printable * 100.0 / sampleSize) << "%\n";
    std::cout << "Control chars:   " << (control * 100.0 / sampleSize) << "%\n";
    std::cout << "Extended ASCII:  " << (extended * 100.0 / sampleSize) << "%\n";
    
    std::string entropyColor;
    std::string entropyDesc;
    if (entropy > 7.5) {
        entropyColor = "\033[91m";
        entropyDesc = "High - Encrypted/Packed";
    } else if (entropy > 6.5) {
        entropyColor = "\033[93m";
        entropyDesc = "Medium - Compressed";
    } else {
        entropyColor = "\033[92m";
        entropyDesc = "Low - Uncompressed";
    }
    
    std::cout << "Entropy:         " << entropyColor << std::fixed << std::setprecision(2) 
              << entropy << "/8.00\033[0m (" << entropyDesc << ")\n";
    
    if (isPE && data.size() > 0x200) {
        std::cout << "\n[*] PE Structure\n";
        std::cout << "----------------\n";
        
        uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
        if (peOffset + 0x100 < data.size()) {
            uint32_t entryPoint = *reinterpret_cast<const uint32_t*>(&data[peOffset + 40]);
            uint32_t imageBase = *reinterpret_cast<const uint32_t*>(&data[peOffset + 52]);
            uint16_t sections = *reinterpret_cast<const uint16_t*>(&data[peOffset + 6]);
            uint32_t timestamp = *reinterpret_cast<const uint32_t*>(&data[peOffset + 8]);
            
            std::cout << "Entry point: \033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << entryPoint << "\033[0m" << std::dec << "\n";
            std::cout << "Image base:  \033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << imageBase << "\033[0m" << std::dec << "\n";
            std::cout << "Sections:    " << sections << "\n";
            std::cout << "Timestamp:   " << timestamp << "\n";
        }
    }
    
    std::cout << "\n[*] Hex Dump (First 256 Bytes)\n";
    std::cout << "------------------------------\n";
    std::cout << "Offset    | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII\n";
    std::cout << "----------+--------------------------------------------------+------------------\n";
    
    size_t dumpSize = std::min(data.size(), static_cast<size_t>(256));
    for (size_t i = 0; i < dumpSize; i += 16) {
        std::cout << "\033[96m" << std::hex << std::setw(8) << std::setfill('0') << i << "\033[0m  | ";
        
        for (size_t j = 0; j < 16 && i + j < dumpSize; j++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(data[i + j]) << " ";
        }
        for (size_t j = dumpSize - i; j < 16; j++) std::cout << "   ";
        
        std::cout << "| ";
        
        for (size_t j = 0; j < 16 && i + j < dumpSize; j++) {
            uint8_t byte = data[i + j];
            if (byte >= 0x20 && byte <= 0x7E) {
                std::cout << static_cast<char>(byte);
            } else {
                std::cout << "\033[90m.\033[0m";
            }
        }
        std::cout << std::dec << "\n";
    }
    
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    CliParser parser;
    CliOptions options = parser.parse(argc, argv);
    
    if (options.showHelp) {
        CliParser::printHelp(argv[0]);
        return 0;
    }
    
    if (options.showVersion) {
        CliParser::printVersion();
        return 0;
    }
    
    if (options.filename.empty()) {
        std::cerr << "Error: No input file specified\n";
        std::cerr << "Use --help for usage information\n";
        return 1;
    }
    
    FileHandler fileHandler(options.filename);
    if (!fileHandler.open()) {
        std::cerr << "Error: Failed to open file\n";
        return 1;
    }
    
    std::vector<uint8_t> data = fileHandler.readAll();
    
    if (data.empty()) {
        std::cerr << "Error: Failed to read file or file is empty\n";
        return 1;
    }
    
    displayBanner();
    
    // Disassembly mode
    if (options.disasmMode) {
        size_t entryPoint = 0;
        BinAnalyzer::Architecture arch;
        
        // User specified architecture or auto-detect
        if (options.architecture != "auto") {
            arch = BinAnalyzer::string_to_architecture(options.architecture);
            entryPoint = (options.offset != 0) ? options.offset : 0;
            
            if (arch == BinAnalyzer::Architecture::AUTO) {
                std::cerr << "Error: Invalid architecture '" << options.architecture << "'\n";
                std::cerr << "Valid options: x86, x64, arm, arm64, thumb, auto\n";
                return 1;
            }
        } else {
            arch = detectArchitecture(data, entryPoint);
            if (options.offset != 0) {
                entryPoint = options.offset;
            }
        }
        
        std::cout << "[*] File: " << options.filename << "\n";
        std::cout << "Architecture: " << BinAnalyzer::architecture_to_string(arch) << "\n";
        std::cout << "Entry Point: 0x" << std::hex << entryPoint << std::dec;
        if (options.offset != 0) {
            std::cout << " (user-specified)";
        } else if (options.architecture != "auto") {
            std::cout << " (user-specified arch)";
        } else {
            std::cout << " (auto-detected)";
        }
        std::cout << "\n\n";
        
        displayDisassembly(data, entryPoint, options.disasmCount, arch);
        return 0;
    }
    
    // Strings-only mode
    if (options.stringsOnly) {
        std::cout << "[*] String Extraction\n";
        std::cout << "---------------------\n";
        
        std::string currentString;
        int count = 0;
        
        for (size_t i = 0; i < data.size(); i++) {
            if (data[i] >= 0x20 && data[i] <= 0x7E) {
                currentString += static_cast<char>(data[i]);
            } else {
                if (currentString.length() >= static_cast<size_t>(options.minStringLength)) {
                    std::cout << currentString << "\n";
                    count++;
                }
                currentString.clear();
            }
        }
        
        std::cout << "\nTotal strings: " << count << "\n";
        return 0;
    }
    
    // Red Team Analysis Mode
    if (options.redTeamMode) {
        displayBasicInfo(data, options.filename);
        
        ImportAnalyzer importAnalyzer;
        ImportAnalysisResult importResult = importAnalyzer.analyze(data);
        importAnalyzer.displayResults(importResult);
        
        SecurityAnalyzer secAnalyzer;
        SecurityAnalysisResult secResult = secAnalyzer.analyze(data);
        secAnalyzer.displayResults(secResult);
        
        AdvancedAnalyzer advancedAnalyzer;
        advancedAnalyzer.runFullAnalysis(data);
        
        return 0;
    }
    
    // Standard mode with quick disassembly
    displayBasicInfo(data, options.filename);
    
    size_t entryPoint = 0;
    BinAnalyzer::Architecture arch = detectArchitecture(data, entryPoint);
    
    if (entryPoint > 0 && entryPoint < data.size()) {
        displayQuickDisassembly(data, entryPoint, arch);
    }
    
    // PE parsing
    if (data.size() >= 2 && data[0] == 0x4D && data[1] == 0x5A) {
        PEParser peParser;
        PEInfo peInfo = peParser.parse(data);
        
        if (peInfo.isPE) {
            std::cout << "[*] PE Header\n";
            std::cout << "-------------\n";
            std::cout << "Architecture: " << peInfo.architecture << "\n";
            std::cout << "Subsystem: " << peInfo.subsystem << "\n";
            std::cout << "Entry point: 0x" << std::hex << peInfo.entryPoint << std::dec << "\n";
            std::cout << "Image base: 0x" << std::hex << peInfo.imageBase << std::dec << "\n";
            std::cout << "Sections: " << peInfo.numberOfSections << "\n";
            std::cout << "Timestamp: " << peInfo.timestamp << "\n";
            std::cout << "\n";
        }
    }
    
    // String extraction
    std::cout << "[*] String Extraction\n";
    std::cout << "---------------------\n";
    
    std::string currentString;
    std::vector<std::string> strings;
    
    for (size_t i = 0; i < data.size(); i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            currentString += static_cast<char>(data[i]);
        } else {
            if (currentString.length() >= static_cast<size_t>(options.minStringLength)) {
                strings.push_back(currentString);
            }
            currentString.clear();
        }
    }
    
    size_t displayCount = std::min(strings.size(), static_cast<size_t>(20));
    for (size_t i = 0; i < displayCount; i++) {
        std::cout << strings[i] << "\n";
    }
    
    if (strings.size() > displayCount) {
        std::cout << "... and " << (strings.size() - displayCount) << " more\n";
    }
    std::cout << "\nTotal strings: " << strings.size() << "\n";
    
    return 0;
}
