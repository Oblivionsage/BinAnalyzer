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
#include "basic_block.hpp"
#include "function_analyzer.hpp"
#include "cfg_analyzer.hpp"
#include "xref_analyzer.hpp"

void displayBanner() {
    std::cout << "\n";
    std::cout << "BinAnalyzer v1.0 - Binary Analysis Tool\n";
    std::cout << "========================================\n\n";
}

BinAnalyzer::Architecture detectArchitecture(const std::vector<uint8_t>& data, size_t& entryPoint) {
    if (data.size() >= 0x200 && data[0] == 0x4D && data[1] == 0x5A) {
        uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
        if (peOffset + 0x100 < data.size()) {
            if (data[peOffset] == 'P' && data[peOffset + 1] == 'E') {
                uint16_t machine = *reinterpret_cast<const uint16_t*>(&data[peOffset + 4]);
                uint32_t entryRVA = *reinterpret_cast<const uint32_t*>(&data[peOffset + 40]);
                entryPoint = entryRVA;
                
                switch (machine) {
                    case 0x014c: return BinAnalyzer::Architecture::X86_32;
                    case 0x8664: return BinAnalyzer::Architecture::X86_64;
                    case 0x01c0: return BinAnalyzer::Architecture::ARM_32;
                    case 0xaa64: return BinAnalyzer::Architecture::ARM_64;
                    case 0x01c2: return BinAnalyzer::Architecture::THUMB;
                }
            }
        }
    }
    else if (data.size() >= 64 && data[0] == 0x7F && data[1] == 0x45) {
        uint8_t elfClass = data[4];
        uint16_t machine = 0;
        
        if (elfClass == 2 && data.size() >= 0x40) {
            machine = *reinterpret_cast<const uint16_t*>(&data[0x12]);
            uint64_t entry = *reinterpret_cast<const uint64_t*>(&data[0x18]);
            if (entry < 0x1000000) entryPoint = static_cast<size_t>(entry);
        } else if (elfClass == 1 && data.size() >= 0x28) {
            machine = *reinterpret_cast<const uint16_t*>(&data[0x12]);
            uint32_t entry = *reinterpret_cast<const uint32_t*>(&data[0x18]);
            if (entry < 0x1000000) entryPoint = static_cast<size_t>(entry);
        }
        
        switch (machine) {
            case 0x03: return BinAnalyzer::Architecture::X86_32;
            case 0x3E: return BinAnalyzer::Architecture::X86_64;
            case 0x28: return BinAnalyzer::Architecture::ARM_32;
            case 0xB7: return BinAnalyzer::Architecture::ARM_64;
        }
    }
    else if (data.size() >= 32) {
        uint32_t magic = *reinterpret_cast<const uint32_t*>(&data[0]);
        
        if (magic == 0xfeedface || magic == 0xcefaedfe) {
            uint32_t cputype = *reinterpret_cast<const uint32_t*>(&data[4]);
            if (cputype == 12) return BinAnalyzer::Architecture::ARM_32;
            if (cputype == 7)  return BinAnalyzer::Architecture::X86_32;
        } else if (magic == 0xfeedfacf || magic == 0xcffaedfe) {
            uint32_t cputype = *reinterpret_cast<const uint32_t*>(&data[4]);
            if (cputype == 0x0100000c) return BinAnalyzer::Architecture::ARM_64;
            if (cputype == 0x01000007) return BinAnalyzer::Architecture::X86_64;
        }
    }
    
    return BinAnalyzer::Architecture::X86_64;
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
            std::cout << "Type: PE (Windows Executable)\n";
            isPE = true;
        } else if (data[0] == 0x7F && data[1] == 0x45) {
            std::cout << "Type: ELF (Linux Binary)\n";
        } else if (data.size() >= 4) {
            uint32_t magic = *reinterpret_cast<const uint32_t*>(&data[0]);
            if (magic == 0xfeedface || magic == 0xcefaedfe || 
                magic == 0xfeedfacf || magic == 0xcffaedfe) {
                std::cout << "Type: Mach-O (macOS/iOS Binary)\n";
            } else {
                std::cout << "Type: Unknown\n";
            }
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
            
            std::cout << "Entry point: 0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << entryPoint << std::dec << "\n";
            std::cout << "Image base:  0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << imageBase << std::dec << "\n";
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

void displayQuickDisasm(const std::vector<BinAnalyzer::Instruction>& instructions, size_t count) {
    std::cout << "[*] Entry Point Disassembly\n";
    std::cout << "---------------------------\n";
    
    size_t displayCount = std::min(instructions.size(), count);
    int calls = 0, jumps = 0;
    
    for (size_t i = 0; i < displayCount; i++) {
        const auto& inst = instructions[i];
        
        bool isCall = (inst.mnemonic == "call" || inst.mnemonic == "bl" || inst.mnemonic == "blx");
        bool isJump = (inst.mnemonic[0] == 'j' || inst.mnemonic[0] == 'b');
        
        if (isCall) calls++;
        if (isJump) jumps++;
        
        std::cout << "\033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                  << inst.address << "\033[0m  ";
        
        if (isCall) {
            std::cout << "\033[91m" << inst.mnemonic << "\033[0m";
        } else if (isJump) {
            std::cout << "\033[93m" << inst.mnemonic << "\033[0m";
        } else {
            std::cout << "\033[90m" << inst.mnemonic << "\033[0m";
        }
        
        if (!inst.operands.empty()) {
            std::cout << " \033[92m" << inst.operands << "\033[0m";
        }
        
        std::cout << "\n" << std::dec;
    }
    
    std::cout << "\n\033[90m[Summary: " << calls << " calls, " << jumps << " jumps]\033[0m\n";
    std::cout << "\033[90mUse --disasm for detailed analysis\033[0m\n\n";
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
        return 1;
    }
    
    FileHandler fileHandler(options.filename);
    if (!fileHandler.open()) {
        std::cerr << "Error: Failed to open file\n";
        return 1;
    }
    
    std::vector<uint8_t> data = fileHandler.readAll();
    if (data.empty()) {
        std::cerr << "Error: File is empty\n";
        return 1;
    }
    
    displayBanner();
    
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
                if (currentString.length() >= options.minStringLength) {
                    std::cout << currentString << "\n";
                    count++;
                }
                currentString.clear();
            }
        }
        
        std::cout << "\nTotal strings: " << count << "\n";
        return 0;
    }
    
    // Detect architecture
    size_t entryPoint = 0;
    BinAnalyzer::Architecture arch;
    
    if (options.architecture != "auto") {
        arch = BinAnalyzer::string_to_architecture(options.architecture);
        entryPoint = (options.offset != 0) ? options.offset : 0;
    } else {
        arch = detectArchitecture(data, entryPoint);
        if (options.offset != 0) entryPoint = options.offset;
    }
    
    // Disassemble (limit to 32K instructions for performance)
    size_t maxSize = std::min(data.size() - entryPoint, static_cast<size_t>(32768));
    const uint8_t* code = data.data() + entryPoint;
    
    BinAnalyzer::Disassembler disasm(arch);
    auto instructions = disasm.disassemble(code, maxSize, entryPoint);
    
    // Limit instructions for analysis in default mode
    if (!options.disasmMode && !options.showBlocks && !options.showFunctions && 
        !options.showCFG && options.xrefAddress == 0) {
        if (instructions.size() > 8192) {
            instructions.resize(8192);
        }
    }
    
    // Basic Block Analysis mode
    if (options.showBlocks) {
        displayBasicInfo(data, options.filename);
        
        BinAnalyzer::BasicBlockAnalyzer bbAnalyzer;
        auto blocks = bbAnalyzer.analyze(instructions);
        
        std::cout << "[*] Basic Blocks\n";
        std::cout << "----------------\n";
        std::cout << "Total blocks: " << blocks.size() << "\n\n";
        
        for (size_t i = 0; i < std::min(blocks.size(), static_cast<size_t>(20)); i++) {
            const auto& block = blocks[i];
            std::cout << "Block #" << (i + 1) << " @ 0x" << std::hex 
                      << block.start_address << std::dec << "\n";
            std::cout << "  Instructions: " << block.size() << "\n";
            std::cout << "  Successors:   " << block.successors.size() << "\n";
            std::cout << "  Predecessors: " << block.predecessors.size() << "\n";
            if (block.ends_with_return) std::cout << "  [RETURNS]\n";
            std::cout << "\n";
        }
        
        if (blocks.size() > 20) {
            std::cout << "... and " << (blocks.size() - 20) << " more blocks\n\n";
        }
        return 0;
    }
    
    // Function Analysis mode
    if (options.showFunctions) {
        displayBasicInfo(data, options.filename);
        
        BinAnalyzer::BasicBlockAnalyzer bbAnalyzer;
        auto blocks = bbAnalyzer.analyze(instructions);
        
        BinAnalyzer::FunctionAnalyzer funcAnalyzer;
        auto functions = funcAnalyzer.analyze(instructions, blocks);
        
        std::cout << "[*] Functions\n";
        std::cout << "-------------\n";
        std::cout << "Total functions: " << functions.size() << "\n\n";
        
        for (const auto& func : functions) {
            std::cout << func.name << " @ 0x" << std::hex << func.start_address;
            if (func.end_address != func.start_address) {
                std::cout << " - 0x" << func.end_address;
            }
            std::cout << std::dec << "\n";
            
            std::cout << "  Instructions: " << func.instruction_count << "\n";
            std::cout << "  Basic blocks: " << func.basic_blocks.size() << "\n";
            std::cout << "  Calls to:     " << func.calls_to.size() << "\n";
            std::cout << "  Called from:  " << func.call_sites.size() << "\n";
            
            if (func.has_prologue) std::cout << "  [PROLOGUE]\n";
            if (func.has_epilogue) std::cout << "  [EPILOGUE]\n";
            std::cout << "\n";
        }
        return 0;
    }
    
    // CFG mode
    if (options.showCFG) {
        displayBasicInfo(data, options.filename);
        
        BinAnalyzer::BasicBlockAnalyzer bbAnalyzer;
        auto blocks = bbAnalyzer.analyze(instructions);
        
        BinAnalyzer::FunctionAnalyzer funcAnalyzer;
        auto functions = funcAnalyzer.analyze(instructions, blocks);
        
        if (!functions.empty()) {
            BinAnalyzer::CFGAnalyzer cfgAnalyzer;
            size_t funcCount = std::min(functions.size(), static_cast<size_t>(3));
            
            for (size_t i = 0; i < funcCount; i++) {
                cfgAnalyzer.generate_cfg(functions[i], blocks);
                cfgAnalyzer.display_cfg(functions[i], blocks);
                cfgAnalyzer.print_statistics(functions[i], blocks);
            }
            
            if (functions.size() > 3) {
                std::cout << "... " << (functions.size() - 3) << " more functions\n\n";
            }
        }
        return 0;
    }
    
    // XRef mode
    if (options.xrefAddress != 0) {
        displayBasicInfo(data, options.filename);
        
        BinAnalyzer::XRefAnalyzer xrefAnalyzer;
        xrefAnalyzer.analyze(instructions);
        xrefAnalyzer.display_xrefs(options.xrefAddress);
        return 0;
    }
    
    // Disasm mode
    if (options.disasmMode) {
        displayBasicInfo(data, options.filename);
        
        std::cout << "[*] Disassembly\n";
        std::cout << "---------------\n";
        std::cout << "Architecture: " << BinAnalyzer::architecture_to_string(arch) << "\n";
        std::cout << "Entry Point: 0x" << std::hex << entryPoint << std::dec << "\n\n";
        
        size_t displayCount = std::min(instructions.size(), options.disasmCount);
        
        for (size_t i = 0; i < displayCount; i++) {
            const auto& inst = instructions[i];
            
            std::cout << "\033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << inst.address << "\033[0m  ";
            std::cout << "\033[93m" << inst.mnemonic << "\033[0m";
            
            if (!inst.operands.empty()) {
                std::cout << " \033[92m" << inst.operands << "\033[0m";
            }
            
            std::cout << "\n" << std::dec;
        }
        
        std::cout << "\nDisassembled " << displayCount << " instructions\n\n";
        return 0;
    }
    
    // DEFAULT MODE: Show everything
    displayBasicInfo(data, options.filename);
    
    // Quick disassembly preview
    if (!instructions.empty()) {
        displayQuickDisasm(instructions, 20);
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
            if (currentString.length() >= options.minStringLength) {
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
    std::cout << "\nTotal strings: " << strings.size() << "\n\n";
    
    // Analysis summary
    BinAnalyzer::BasicBlockAnalyzer bbAnalyzer;
    auto blocks = bbAnalyzer.analyze(instructions);
    
    BinAnalyzer::FunctionAnalyzer funcAnalyzer;
    auto functions = funcAnalyzer.analyze(instructions, blocks);
    
    BinAnalyzer::XRefAnalyzer xrefAnalyzer;
    auto xrefs = xrefAnalyzer.analyze(instructions);
    
    std::cout << "[*] Code Analysis Summary\n";
    std::cout << "-------------------------\n";
    std::cout << "Architecture:  " << BinAnalyzer::architecture_to_string(arch) << "\n";
    std::cout << "Entry Point:   0x" << std::hex << entryPoint << std::dec << "\n";
    std::cout << "Instructions:  " << instructions.size() << " \033[90m(use --disasm)\033[0m\n";
    std::cout << "Basic Blocks:  " << blocks.size() << " \033[90m(use --blocks)\033[0m\n";
    std::cout << "Functions:     " << functions.size() << " \033[90m(use --functions)\033[0m\n";
    std::cout << "Cross-refs:    " << xrefs.size() << " \033[90m(use --xref <addr>)\033[0m\n";
    std::cout << "\033[90mControl Flow:  (use --cfg)\033[0m\n";
    std::cout << "\n";
    
    return 0;
}

// TODO: Add multi-threading support
// TODO: Implement progress bar for large files
