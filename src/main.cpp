#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <cmath>
#include <set>
#include <array>
#include "cli_parser.hpp"
#include "file_handler.hpp"
#include "hex_viewer.hpp"
#include "string_analyzer.hpp"
#include "disassembler.hpp"
#include "basic_block.hpp"
#include "function_analyzer.hpp"
#include "cfg_analyzer.hpp"
#include "xref_analyzer.hpp"
#include "hash_calculator.hpp"
#include "advanced_analyzer.hpp"

void displayBanner() {
    std::cout << "\n\033[1;96mBinAnalyzer v1.0\033[0m - Binary Analysis Tool\n";
    std::cout << "========================================\n\n";
}

void displayFileInfo(const std::string& filename, size_t filesize, const std::string& md5, 
                     const std::string& sha256, const std::string& filetype) {
    std::cout << "[*] File Analysis\n";
    std::cout << "-----------------\n";
    std::cout << "File: " << filename << "\n";
    std::cout << "Size: " << filesize << " bytes (" << std::fixed << std::setprecision(2) 
              << (filesize / 1024.0) << " KB)\n";
    std::cout << "MD5:    " << md5 << "\n";
    std::cout << "SHA256: " << sha256 << "\n";
    std::cout << "Type: " << filetype << "\n\n";
}

void displayByteStats(const std::vector<uint8_t>& data) {
    size_t sampleSize = std::min(data.size(), size_t(8192));
    size_t nullBytes = 0, printable = 0, control = 0, extended = 0;
    
    for (size_t i = 0; i < sampleSize; i++) {
        uint8_t byte = data[i];
        if (byte == 0) nullBytes++;
        else if (byte >= 0x20 && byte <= 0x7E) printable++;
        else if (byte < 0x20) control++;
        else extended++;
    }
    
    std::array<int, 256> freq = {};
    for (size_t i = 0; i < sampleSize; i++) freq[data[i]]++;
    
    double entropy = 0.0;
    for (int count : freq) {
        if (count > 0) {
            double p = count / static_cast<double>(sampleSize);
            entropy -= p * log2(p);
        }
    }
    
    std::cout << "[*] Byte Statistics\n";
    std::cout << "-------------------\n";
    std::cout << "NULL bytes:      " << std::fixed << std::setprecision(2) 
              << (nullBytes * 100.0 / sampleSize) << "%\n";
    std::cout << "Printable ASCII: " << (printable * 100.0 / sampleSize) << "%\n";
    std::cout << "Control chars:   " << (control * 100.0 / sampleSize) << "%\n";
    std::cout << "Extended ASCII:  " << (extended * 100.0 / sampleSize) << "%\n";
    std::cout << "Entropy:         " << std::setprecision(2) << entropy << "/8.00";
    
    if (entropy < 5.0) std::cout << " (Low - Uncompressed)\n\n";
    else if (entropy < 7.0) std::cout << " (Medium)\n\n";
    else std::cout << " (High - Packed/Encrypted)\n\n";
}

void displayBasicInfo(const std::vector<uint8_t>& data, const std::string& filepath) {
    bool isPE = data.size() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
    
    if (isPE) {
        std::cout << "[*] PE Structure\n";
        std::cout << "----------------\n";
        
        if (data.size() >= 0x3C + 4) {
            uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
            
            if (peOffset + 0x18 < data.size()) {
                uint16_t magic = *reinterpret_cast<const uint16_t*>(&data[peOffset + 0x18]);
                uint32_t timestamp = *reinterpret_cast<const uint32_t*>(&data[peOffset + 8]);
                uint16_t numSections = *reinterpret_cast<const uint16_t*>(&data[peOffset + 6]);
                
                if (magic == 0x020B && peOffset + 0x38 < data.size()) {  // PE32+ (64-bit)
                    uint32_t entryRVA = *reinterpret_cast<const uint32_t*>(&data[peOffset + 0x28]);
                    uint64_t imageBase = *reinterpret_cast<const uint64_t*>(&data[peOffset + 0x30]);
                    
                    std::cout << "Entry point: 0x" << std::hex << std::setw(8) << std::setfill('0') 
                              << entryRVA << " (RVA)" << std::dec << "\n";
                    std::cout << "Image base:  0x" << std::hex << std::setw(16) << std::setfill('0') 
                              << imageBase << std::dec << "\n";
                    std::cout << "Entry VA:    0x" << std::hex << std::setw(16) << std::setfill('0') 
                              << (imageBase + entryRVA) << std::dec << "\n";
                    std::cout << "Sections:    " << numSections << "\n";
                    std::cout << "Timestamp:   " << timestamp << "\n\n";
                    
                } else if (magic == 0x010B && peOffset + 0x34 < data.size()) {  // PE32 (32-bit)
                    uint32_t entryRVA = *reinterpret_cast<const uint32_t*>(&data[peOffset + 0x28]);
                    uint32_t imageBase = *reinterpret_cast<const uint32_t*>(&data[peOffset + 0x34]);
                    
                    std::cout << "Entry point: 0x" << std::hex << std::setw(8) << std::setfill('0') 
                              << entryRVA << " (RVA)" << std::dec << "\n";
                    std::cout << "Image base:  0x" << std::hex << std::setw(8) << std::setfill('0') 
                              << imageBase << std::dec << "\n";
                    std::cout << "Entry VA:    0x" << std::hex << std::setw(8) << std::setfill('0') 
                              << (imageBase + entryRVA) << std::dec << "\n";
                    std::cout << "Sections:    " << numSections << "\n";
                    std::cout << "Timestamp:   " << timestamp << "\n\n";
                }
            }
        }
    }
    
    std::cout << "[*] Hex Dump (First 256 Bytes)\n";
    std::cout << "------------------------------\n";
    std::cout << "Offset    | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII\n";
    std::cout << "----------+--------------------------------------------------+------------------\n";
    
    size_t dumpSize = std::min(size_t(256), data.size());
    for (size_t i = 0; i < dumpSize; i += 16) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << i << "  | ";
        
        for (size_t j = 0; j < 16; j++) {
            if (i + j < dumpSize) {
                std::cout << std::setw(2) << std::setfill('0') << (int)data[i + j] << " ";
            } else {
                std::cout << "   ";
            }
        }
        
        std::cout << "| ";
        for (size_t j = 0; j < 16 && i + j < dumpSize; j++) {
            uint8_t c = data[i + j];
            std::cout << (c >= 0x20 && c <= 0x7E ? (char)c : '.');
        }
        std::cout << "\n";
    }
    std::cout << std::dec << "\n";
}

void displayQuickDisasm(const std::vector<BinAnalyzer::Instruction>& instructions, size_t count) {
    std::cout << "[*] Entry Point Disassembly\n";
    std::cout << "---------------------------\n";
    
    size_t calls = 0, jumps = 0;
    for (size_t i = 0; i < std::min(count, instructions.size()); i++) {
        const auto& inst = instructions[i];
        std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << inst.address 
                  << "  " << std::setw(12) << std::left << std::setfill(' ') << inst.mnemonic 
                  << " " << inst.operands << "\n" << std::dec;
        
        if (inst.mnemonic.find("call") != std::string::npos) calls++;
        if (inst.mnemonic.find("j") == 0) jumps++;
    }
    
    std::cout << "\n[Summary: " << calls << " calls, " << jumps << " jumps]\n";
    std::cout << "Use --disasm for detailed analysis\n\n";
}

int main(int argc, char* argv[]) {
    CliParser cliParser;
    auto options = cliParser.parse(argc, argv);
    
    if (options.showHelp) {
        std::cout << "Usage: binanalyzer [options] <file>\n\n";
        std::cout << "Options:\n";
        std::cout << "  --disasm          Full disassembly\n";
        std::cout << "  --functions       Function analysis\n";
        std::cout << "  --blocks          Basic block analysis\n";
        std::cout << "  --cfg             Control flow graph\n";
        std::cout << "  --xref <addr>     Cross-references\n";
        std::cout << "  --help            Show this help\n";
        return 0;
    }
    
    if (options.filename.empty()) {
        std::cerr << "Error: No input file specified\n";
        return 1;
    }
    
    FileHandler fileHandler(options.filename);
    if (!fileHandler.open()) {
        std::cerr << "Error: Could not open file\n";
        return 1;
    }
    
    auto data = fileHandler.readAll();
    fileHandler.close();
    
    if (data.empty()) {
        std::cerr << "Error: File is empty\n";
        return 1;
    }
    
    displayBanner();
    
    // Calculate hashes
    HashCalculator hashCalc;
    std::string md5Hash = hashCalc.calculateMD5(data);
    std::string sha256Hash = hashCalc.calculateSHA256(data);
    
    // Get file type
    std::string filetype = "Unknown";
    if (data.size() >= 4) {
        if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') 
            filetype = "ELF (Linux Binary)";
        else if (data[0] == 'M' && data[1] == 'Z') 
            filetype = "PE (Windows Executable)";
        else if (data[0] == 0xCF && data[1] == 0xFA) 
            filetype = "Mach-O (macOS Binary)";
    }
    
    displayFileInfo(options.filename, data.size(), md5Hash, sha256Hash, filetype);
    displayByteStats(data);
    displayBasicInfo(data, options.filename);
    
    // Detect architecture and entry point
    uint64_t entryPoint = 0;
    BinAnalyzer::Architecture arch = BinAnalyzer::Architecture::AUTO;
    
    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        // ELF parsing
        if (data.size() >= 0x18) {
            entryPoint = *reinterpret_cast<const uint64_t*>(&data[0x18]);
        }
        if (data.size() >= 0x12) {
            uint16_t machine = *reinterpret_cast<const uint16_t*>(&data[0x12]);
            if (machine == 0x3E) arch = BinAnalyzer::Architecture::X86_64;
            else if (machine == 0xB7) arch = BinAnalyzer::Architecture::ARM_64;
        }
    } else if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
        // PE parsing
        if (data.size() >= 0x3C + 4) {
            uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
            
            if (peOffset + 0x18 < data.size()) {
                uint16_t machine = *reinterpret_cast<const uint16_t*>(&data[peOffset + 4]);
                uint16_t magic = *reinterpret_cast<const uint16_t*>(&data[peOffset + 0x18]);
                
                if (magic == 0x020B && peOffset + 0x38 < data.size()) {  // PE32+ (64-bit)
                    uint32_t rvaEntry = *reinterpret_cast<const uint32_t*>(&data[peOffset + 0x28]);
                    uint64_t imageBase = *reinterpret_cast<const uint64_t*>(&data[peOffset + 0x30]);
                    entryPoint = imageBase + rvaEntry;
                    
                    if (machine == 0x8664) arch = BinAnalyzer::Architecture::X86_64;
                    else if (machine == 0xAA64) arch = BinAnalyzer::Architecture::ARM_64;
                    
                } else if (magic == 0x010B && peOffset + 0x34 < data.size()) {  // PE32 (32-bit)
                    uint32_t rvaEntry = *reinterpret_cast<const uint32_t*>(&data[peOffset + 0x28]);
                    uint32_t imageBase = *reinterpret_cast<const uint32_t*>(&data[peOffset + 0x34]);
                    entryPoint = imageBase + rvaEntry;
                    
                    if (machine == 0x014C) arch = BinAnalyzer::Architecture::X86_32;
                }
            }
        }
    }
    
    // Disassemble
    BinAnalyzer::Disassembler disasm(arch);
    auto instructions = disasm.disassemble(data.data(), data.size(), entryPoint);
    
    // Analyze
    BinAnalyzer::BasicBlockAnalyzer bbAnalyzer;
    auto blocks = bbAnalyzer.analyze(instructions);
    
    BinAnalyzer::FunctionAnalyzer funcAnalyzer;
    auto functions = funcAnalyzer.analyze(instructions, blocks);
    
    BinAnalyzer::XRefAnalyzer xrefAnalyzer;
    auto xrefs = xrefAnalyzer.analyze(instructions);
    
    // MODE: Disassembly
    if (options.disasmMode) {
        std::cout << "[*] Full Disassembly\n";
        std::cout << "────────────────────\n\n";
        for (const auto& inst : instructions) {
            std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << inst.address 
                      << "  " << std::setw(12) << std::left << std::setfill(' ') << inst.mnemonic 
                      << " " << inst.operands << "\n" << std::dec;
        }
        return 0;
    }
    
    // MODE: Functions
    if (options.showFunctions) {
        std::cout << "[*] Function Analysis (" << functions.size() << " functions)\n";
        std::cout << "──────────────────────────────────────────────────────────\n\n";
        for (const auto& func : functions) {
            std::cout << func.name << " @ 0x" << std::hex << func.start_address;
            if (func.end_address != func.start_address) {
                std::cout << " - 0x" << func.end_address;
            }
            std::cout << std::dec << "\n";
            
            std::cout << "  Instructions: " << func.instruction_count 
                      << " | Blocks: " << func.basic_blocks.size()
                      << " | Complexity: " << func.complexity
                      << " | Convention: " << func.calling_convention << "\n";
            std::cout << "  Calls to: " << func.calls_to.size() 
                      << " | Called from: " << func.call_sites.size();
            
            if (func.has_prologue) std::cout << " [PROLOGUE]";
            if (func.has_epilogue) std::cout << " [EPILOGUE]";
            if (func.is_leaf) std::cout << " [LEAF]";
            if (func.is_recursive) std::cout << " [RECURSIVE]";
            std::cout << "\n\n";
        }
        return 0;
    }
    
    // MODE: Basic Blocks
    if (options.showBlocks) {
        std::cout << "[*] Basic Block Analysis (" << blocks.size() << " blocks)\n";
        std::cout << "───────────────────────────────────────────────────────────\n\n";
        int count = 0;
        for (const auto& block : blocks) {
            count++;
            std::cout << "Block #" << count << " @ 0x" << std::hex << block.start_address << std::dec << "\n";
            std::cout << "  Instructions: " << block.instructions.size()
                      << " | Successors: " << block.successors.size()
                      << " | Predecessors: " << block.predecessors.size();
            
            if (block.is_function_entry) std::cout << " [ENTRY]";
            if (block.ends_with_return) std::cout << " [RETURNS]";
            if (block.ends_with_call) std::cout << " [CALLS]";
            std::cout << "\n\n";
        }
        return 0;
    }
    
    // MODE: CFG
    if (options.showCFG) {
        std::cout << "[*] Control Flow Graph Analysis\n";
        std::cout << "────────────────────────────────────────\n\n";
        for (const auto& func : functions) {
            BinAnalyzer::CFGAnalyzer cfgAnalyzer;
            cfgAnalyzer.display_cfg(func, blocks);
            cfgAnalyzer.print_statistics(func, blocks);
        }
        return 0;
    }
    
    // MODE: XRefs
    if (options.xrefAddress != 0) {
        std::cout << "[*] Cross-References for 0x" << std::hex << options.xrefAddress << std::dec << "\n";
        std::cout << "──────────────────────────────────────────────\n\n";
        
        bool found = false;
        for (const auto& xref : xrefs) {
            if (xref.to_address == options.xrefAddress) {
                std::cout << "0x" << std::hex << xref.from_address << " -> 0x" << xref.to_address 
                          << " [" << xref.type << "]\n" << std::dec;
                found = true;
            }
        }
        
        if (!found) {
            std::cout << "No cross-references found for this address.\n";
        }
        return 0;
    }
    
    // DEFAULT MODE: Show entry point disasm + strings + analysis
    displayQuickDisasm(instructions, 20);
    
    // String extraction
    std::cout << "[*] String Extraction\n";
    std::cout << "---------------------\n";
    
    std::string currentString;
    std::vector<std::string> strings;
    for (size_t i = 0; i < data.size(); i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            currentString += static_cast<char>(data[i]);
        } else {
            if (currentString.length() >= options.minStringLength) {
                strings.push_back(currentString);
            }
            currentString.clear();
        }
    }
    
    size_t displayCount = std::min(strings.size(), size_t(20));
    for (size_t i = 0; i < displayCount; i++) {
        std::cout << strings[i] << "\n";
    }
    
    if (strings.size() > displayCount) {
        std::cout << "... and " << (strings.size() - displayCount) << " more\n";
    }
    std::cout << "\nTotal strings: " << strings.size() << "\n\n";
    
    // Calculate stats
    int leaf_count = 0, recursive_count = 0, complex_count = 0;
    int call_xrefs = 0, jump_xrefs = 0, data_xrefs = 0, total_loops = 0;
    
    for (const auto& func : functions) {
        if (func.is_leaf) leaf_count++;
        if (func.is_recursive) recursive_count++;
        if (func.complexity > 10) complex_count++;
        
        BinAnalyzer::CFGAnalyzer cfgAnalyzer;
        auto loops = cfgAnalyzer.detect_loops(func, blocks);
        total_loops += loops.size();
    }
    
    for (const auto& xref : xrefs) {
        if (xref.type == "call") call_xrefs++;
        else if (xref.type == "jump") jump_xrefs++;
        else data_xrefs++;
    }
    
    double avg_complexity = 0.0;
    if (!functions.empty()) {
        BinAnalyzer::CFGAnalyzer cfgAnalyzer;
        avg_complexity = cfgAnalyzer.get_average_complexity(functions);
    }
    
    // Analysis Summary
    std::cout << "[*] Code Analysis Summary\n";
    std::cout << "-------------------------\n";
    std::cout << "Architecture:  " << BinAnalyzer::architecture_to_string(arch) << "\n";
    std::cout << "Entry Point:   0x" << std::hex << entryPoint << std::dec << "\n";
    std::cout << "Instructions:  " << instructions.size() << " (use --disasm)\n";
    std::cout << "Basic Blocks:  " << blocks.size() << " (use --blocks)\n";
    std::cout << "Functions:     " << functions.size() << " (use --functions)\n";
    std::cout << "  - Leaf:      " << leaf_count << "\n";
    std::cout << "  - Recursive: " << recursive_count << "\n";
    std::cout << "  - Complex:   " << complex_count << " (complexity > 10)\n";
    std::cout << "Cross-refs:    " << xrefs.size() << " (use --xref <addr>)\n";
    std::cout << "  - Calls:     " << call_xrefs << "\n";
    std::cout << "  - Jumps:     " << jump_xrefs << "\n";
    std::cout << "  - Data:      " << data_xrefs << "\n";
    std::cout << "Control Flow:  (use --cfg)\n";
    std::cout << "  - Loops:     " << total_loops << "\n";
    std::cout << "  - Avg Complexity: " << std::fixed << std::setprecision(1) << avg_complexity << "\n\n";
    
    return 0;
}
