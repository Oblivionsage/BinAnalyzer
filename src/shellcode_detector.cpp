#include "shellcode_detector.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>

ShellcodeDetector::ShellcodeDetector() {
    initializePatterns();
}

void ShellcodeDetector::initializePatterns() {
    ShellcodePattern getpc_call;
    getpc_call.type = ShellcodeType::GETPC_CALL;
    getpc_call.signature = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58};
    getpc_call.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    getpc_call.description = "GetPC (CALL/POP)";
    patterns_.push_back(getpc_call);
    
    ShellcodePattern fnstenv;
    fnstenv.type = ShellcodeType::GETPC_FNSTENV;
    fnstenv.signature = {0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4};
    fnstenv.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    fnstenv.description = "GetPC (FNSTENV)";
    patterns_.push_back(fnstenv);
    
    ShellcodePattern egg_hunter;
    egg_hunter.type = ShellcodeType::EGG_HUNTER;
    egg_hunter.signature = {0x66, 0x81, 0xCA, 0xFF, 0x0F};
    egg_hunter.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    egg_hunter.description = "Egg hunter";
    patterns_.push_back(egg_hunter);
    
    ShellcodePattern metasploit;
    metasploit.type = ShellcodeType::METASPLOIT_PATTERN;
    metasploit.signature = {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00};
    metasploit.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    metasploit.description = "Metasploit stub";
    patterns_.push_back(metasploit);
    
    ShellcodePattern winexec;
    winexec.type = ShellcodeType::REVERSE_SHELL;
    winexec.signature = {0x68, 0x63, 0x61, 0x6C, 0x63};
    winexec.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    winexec.description = "WinExec shellcode";
    patterns_.push_back(winexec);
}

ShellcodeAnalysisResult ShellcodeDetector::analyze(const std::vector<uint8_t>& data) {
    ShellcodeAnalysisResult result;
    result.shellcodeFound = false;
    result.totalPatterns = 0;
    
    if (data.size() < 100) return result;
    
    std::cout << "\033[93m[*] Scanning for shellcode patterns...\033[0m\n";
    
    size_t scanSize = std::min(data.size(), static_cast<size_t>(2 * 1024 * 1024));
    
    // NOP sled detection
    for (size_t i = 0; i < scanSize - 20; i++) {
        if (detectNOPSled(data, i)) {
            ShellcodeDetection detection;
            detection.type = ShellcodeType::NOP_SLED;
            detection.offset = i;
            detection.description = "NOP sled";
            detection.confidence = 0.7;
            
            size_t nopLen = 0;
            while (i + nopLen < scanSize && data[i + nopLen] == 0x90) nopLen++;
            detection.length = nopLen;
            
            result.detections.push_back(detection);
            result.shellcodeFound = true;
            i += nopLen;
            
            if (result.detections.size() >= 20) break;
        }
    }
    
    // Pattern matching
    for (size_t i = 0; i < scanSize - 20; i++) {
        for (const auto& pattern : patterns_) {
            if (matchPattern(data, i, pattern.signature, pattern.mask)) {
                ShellcodeDetection detection;
                detection.type = pattern.type;
                detection.offset = i;
                detection.length = pattern.signature.size();
                detection.description = pattern.description;
                detection.confidence = 0.8;
                
                result.detections.push_back(detection);
                result.shellcodeFound = true;
                
                if (result.detections.size() >= 20) break;
            }
        }
        if (result.detections.size() >= 20) break;
    }
    
    result.totalPatterns = result.detections.size();
    return result;
}

bool ShellcodeDetector::matchPattern(const std::vector<uint8_t>& data, size_t offset,
                                      const std::vector<uint8_t>& pattern,
                                      const std::vector<uint8_t>& mask) {
    if (offset + pattern.size() > data.size()) return false;
    
    for (size_t i = 0; i < pattern.size(); i++) {
        if ((data[offset + i] & mask[i]) != (pattern[i] & mask[i])) return false;
    }
    return true;
}

bool ShellcodeDetector::detectNOPSled(const std::vector<uint8_t>& data, size_t offset) {
    const size_t MIN_NOP_COUNT = 20;
    if (offset + MIN_NOP_COUNT > data.size()) return false;
    
    for (size_t i = 0; i < MIN_NOP_COUNT; i++) {
        if (data[offset + i] != 0x90) return false;
    }
    return true;
}

void ShellcodeDetector::displayResults(const ShellcodeAnalysisResult& result) {
    if (result.detections.empty()) return;
    
    std::cout << "\n[*] Shellcode Analysis\n";
    std::cout << "----------------------\n";
    std::cout << "Patterns detected: \033[91m" << result.totalPatterns << "\033[0m\n\n";
    
    size_t displayCount = std::min(result.detections.size(), static_cast<size_t>(8));
    for (size_t i = 0; i < displayCount; i++) {
        const auto& detection = result.detections[i];
        std::cout << "  \033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                  << detection.offset << "\033[0m" << std::dec 
                  << "  " << detection.description << "\n";
    }
    
    if (result.detections.size() > displayCount) {
        std::cout << "  ... and " << (result.detections.size() - displayCount) << " more\n";
    }
    std::cout << "\n";
}
