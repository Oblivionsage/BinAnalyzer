#include <iostream>
#include <iomanip>
#include "file_handler.hpp"
#include "hex_viewer.hpp"
#include "hash_calculator.hpp"
#include "pe_parser.hpp"
#include "cli_parser.hpp"
#include "import_analyzer.hpp"

int main(int argc, char* argv[]) {
    // Parse command-line arguments first
    CliOptions options = CliParser::parse(argc, argv);
    
    if (options.showHelp) {
        HexViewer::displayBanner();
        CliParser::printHelp(argv[0]);
        return 0;
    }
    
    if (options.showVersion) {
        HexViewer::displayBanner();
        CliParser::printVersion();
        return 0;
    }
    
    // Display banner for normal operations
    HexViewer::displayBanner();

    // Open file
    FileHandler fileHandler(options.filename);
    if (!fileHandler.open()) {
        std::cerr << "\n\033[91m[!] Error:\033[0m Could not open file '" << options.filename << "'\n\n";
        return 1;
    }

    // Read file data
    std::vector<uint8_t> data = fileHandler.readAll();
    
    // Strings-only mode
    if (options.stringsOnly) {
        PEParser peParser;
        std::vector<std::string> strings = peParser.extractStrings(data, options.minStringLength);
        
        std::cout << "\n\033[1;96m[*] File:\033[0m " << options.filename << "\n";
        std::cout << "\033[1;96m[*] Extracted Strings\033[0m (min length " << options.minStringLength << "):\n";
        std::cout << "\033[90m────────────────────────────────────────────────────────\033[0m\n";
        
        for (const auto& str : strings) {
            std::cout << "  " << str << "\n";
        }
        
        std::cout << "\n\033[92m[+] Total: " << strings.size() << " strings found\033[0m\n\n";
        fileHandler.close();
        return 0;
    }
    
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
    std::cout << "\033[96m[*] Calculating file hashes...\033[0m\n";
    std::string md5 = HashCalculator::calculateMD5(data);
    std::string sha256 = HashCalculator::calculateSHA256(data);
    
    // Display results
    HexViewer viewer;
    viewer.setColorEnabled(!options.noColor);
    viewer.displayHeader(options.filename, fileHandler.getSize(), fileType);
    viewer.displayFileInfo(md5, sha256);
    viewer.displayStatistics(data);
    
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
    
    // Display hex view with custom offset and length
    viewer.displayHex(data, options.offset, options.length);
    
    // Import Table Analysis (Red Team Mode)
    if (options.redTeamMode) {
        std::cout << "\033[93m[!] Note: Red Team analysis currently supports PE files only\033[0m\n";
        std::cout << "\033[93m[!] String-based detection may produce false positives\033[0m\n";
        std::cout << "\033[93m[!] Future: Full import table parsing for accurate results\033[0m\n\n";
        
        ImportAnalyzer importAnalyzer;
        ImportAnalysisResult importResult = importAnalyzer.analyze(data);
        
        if (importResult.suspiciousCount > 0) {
            importAnalyzer.displayResults(importResult);
        } else {
            std::cout << "\033[92m[+] No suspicious imports detected\033[0m\n\n";
        }
    }

    // Extract and display strings
    std::vector<std::string> strings = peParser.extractStrings(data, options.minStringLength);
    
    if (!strings.empty()) {
        std::cout << "\n\033[96m[*] Extracted Strings\033[0m (min length " << options.minStringLength << ", showing first 20):\n";
        std::cout << "\033[90m────────────────────────────────────────────────────────\033[0m\n";
        
        size_t count = 0;
        for (const auto& str : strings) {
            if (count >= 20) break;
            std::cout << "  " << str << "\n";
            count++;
        }
        
        if (strings.size() > 20) {
            std::cout << "  \033[90m... and " << (strings.size() - 20) << " more strings\033[0m\n";
        }
    }
    
    std::cout << "\n\033[92m[+] Analysis complete!\033[0m\n\n";
    
    fileHandler.close();
    return 0;
}
