#include <iostream>
#include <iomanip>
#include "file_handler.hpp"
#include "hex_viewer.hpp"
#include "hash_calculator.hpp"
#include "pe_parser.hpp"

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <binary_file>\n";
    std::cout << "\nBinAnalyzer - Modern Binary Analysis Tool\n";
    std::cout << "Analyze binary files with hex view, hash calculation, and PE parsing\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string filename = argv[1];
    
    // Open file
    FileHandler fileHandler(filename);
    if (!fileHandler.open()) {
        std::cerr << "Error: Could not open file '" << filename << "'\n";
        return 1;
    }

    // Read file data
    std::vector<uint8_t> data = fileHandler.readAll();
    
    // Parse PE if applicable
    PEParser peParser;
    PEInfo peInfo = peParser.parse(data);
    
    std::string fileType = "Unknown";
    if (peInfo.isPE) {
        fileType = "PE Executable (" + peInfo.architecture + ", " + peInfo.subsystem + ")";
    } else if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        fileType = "ELF Executable";
    }
    
    // Calculate hashes
    std::cout << "\n[*] Calculating file hashes...\n";
    std::string md5 = HashCalculator::calculateMD5(data);
    std::string sha256 = HashCalculator::calculateSHA256(data);
    
    // Display results
    HexViewer viewer;
    viewer.displayHeader(filename, fileHandler.getSize(), fileType);
    viewer.displayFileInfo(md5, sha256);
    
    // Display PE info if available
    if (peInfo.isPE) {
        std::cout << "║                                                                                       ║\n";
        std::cout << "║  " << "\033[1m" << "PE Information:" << "\033[0m" << "                                                                     ║\n";
        std::cout << "║  Entry Point:  0x" << std::hex << std::setfill('0') << std::setw(8) << peInfo.entryPoint << std::dec;
        std::cout << "                                                            ║\n";
        std::cout << "║  Image Base:   0x" << std::hex << std::setfill('0') << std::setw(8) << peInfo.imageBase << std::dec;
        std::cout << "                                                            ║\n";
        std::cout << "║  Sections:     " << peInfo.numberOfSections;
        std::cout << "                                                                           ║\n";
        std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════╣\n";
    }
    
    // Display hex view (first 256 bytes)
    viewer.displayHex(data, 0, 256);
    
    // Extract and display strings
    std::vector<std::string> strings = peParser.extractStrings(data, 5);
    
    if (!strings.empty()) {
        std::cout << "\n[*] Extracted Strings (min length 5, showing first 20):\n";
        std::cout << "────────────────────────────────────────────────────────\n";
        
        size_t count = 0;
        for (const auto& str : strings) {
            if (count >= 20) break;
            std::cout << "  " << str << "\n";
            count++;
        }
        
        if (strings.size() > 20) {
            std::cout << "  ... and " << (strings.size() - 20) << " more strings\n";
        }
    }
    
    std::cout << "\n[+] Analysis complete!\n\n";
    
    fileHandler.close();
    return 0;
}
