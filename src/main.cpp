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

void displayBanner() {
    std::cout << "\n";
    std::cout << "BinAnalyzer v1.0 - Binary Analysis Tool\n";
    std::cout << "========================================\n\n";
}

void displayBasicInfo(const std::vector<uint8_t>& data, const std::string& filepath) {
    std::cout << "[*] File Analysis\n";
    std::cout << "-----------------\n";
    std::cout << "File: " << filepath << "\n";
    std::cout << "Size: " << data.size() << " bytes (" 
              << std::fixed << std::setprecision(2) 
              << (data.size() / 1024.0) << " KB)\n";
    
    // Hash calculation
    HashCalculator hashCalc;
    std::string md5 = hashCalc.calculateMD5(data);
    std::string sha256 = hashCalc.calculateSHA256(data);
    std::cout << "MD5:    " << md5 << "\n";
    std::cout << "SHA256: " << sha256 << "\n";
    
    // File type detection
    bool isPE = false;
    if (data.size() >= 2) {
        if (data[0] == 0x4D && data[1] == 0x5A) {
            std::cout << "Type: \033[93mPE (Windows Executable)\033[0m\n";
            isPE = true;
        } else if (data[0] == 0x7F && data[1] == 0x45) {
            std::cout << "Type: ELF (Linux Binary)\n";
        } else {
            std::cout << "Type: Unknown\n";
        }
    }
    
    // Statistics
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
    
    // PE Information
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
    
    // Hex dump (first 256 bytes)
    std::cout << "\n[*] Hex Dump (First 256 Bytes)\n";
    std::cout << "------------------------------\n";
    std::cout << "Offset    | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII\n";
    std::cout << "----------+--------------------------------------------------+------------------\n";
    
    size_t dumpSize = std::min(data.size(), static_cast<size_t>(256));
    for (size_t i = 0; i < dumpSize; i += 16) {
        std::cout << "\033[96m" << std::hex << std::setw(8) << std::setfill('0') << i << "\033[0m  | ";
        
        // Hex
        for (size_t j = 0; j < 16 && i + j < dumpSize; j++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(data[i + j]) << " ";
        }
        for (size_t j = dumpSize - i; j < 16; j++) std::cout << "   ";
        
        std::cout << "| ";
        
        // ASCII
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
    
      // Load file TODO mem
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
    
    // Standard mode
    displayBasicInfo(data, options.filename);
    
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
    
    // Hex viewer
    std::cout << "[*] Hex Dump\n";
    std::cout << "------------\n";
    
    HexViewer hexViewer;
    hexViewer.displayHex(data, options.offset, options.length);
    
    // String extraction
    std::cout << "\n[*] String Extraction\n";
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
