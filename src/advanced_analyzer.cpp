#include "advanced_analyzer.hpp"
#include <iostream>

AdvancedAnalyzer::AdvancedAnalyzer() 
    : packerDetector_(), shellcodeDetector_(), iocExtractor_(), stringAnalyzer_() {
}

void AdvancedAnalyzer::runFullAnalysis(const std::vector<uint8_t>& data) {
    std::cout << "\n";
    std::cout << "[*] Advanced Analysis\n";
    std::cout << "--------------------\n\n";
    
    // Stage 1: Packer Detection
    auto packerResult = packerDetector_.detect(data);
    packerDetector_.displayResults(packerResult);
    
    // Stage 2: Shellcode Analysis
    auto shellcodeResult = shellcodeDetector_.analyze(data);
    shellcodeDetector_.displayResults(shellcodeResult);
    
    // Stage 3: Network IOC Extraction
    auto iocResult = iocExtractor_.extract(data);
    iocExtractor_.displayResults(iocResult);
    
    // Stage 4: Suspicious Strings
    auto stringResult = stringAnalyzer_.analyze(data);
    stringAnalyzer_.displayResults(stringResult);
    
    std::cout << "[*] Analysis complete\n\n";
}
