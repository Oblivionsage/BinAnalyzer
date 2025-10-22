#include "pe_parser.hpp"
#include <cstring>
#include <algorithm>

PEParser::PEParser() {
}

bool PEParser::isPEFile(const std::vector<uint8_t>& data) {
    return isValidPESignature(data);
}

bool PEParser::isValidPESignature(const std::vector<uint8_t>& data) {
    if (data.size() < 64) return false;
    
    // Check for MZ signature
    if (data[0] != 0x4D || data[1] != 0x5A) {
        return false;
    }
    
    return true;
}

uint32_t PEParser::getPEHeaderOffset(const std::vector<uint8_t>& data) {
    if (data.size() < 64) return 0;
    
    // PE header offset is at 0x3C
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    return peOffset;
}

PEInfo PEParser::parse(const std::vector<uint8_t>& data) {
    PEInfo info;
    info.isPE = false;
    
    if (!isValidPESignature(data)) {
        return info;
    }
    
    info.isPE = true;
    
    uint32_t peOffset = getPEHeaderOffset(data);
    
    if (peOffset + 4 > data.size()) {
        return info;
    }
    
    // Check PE signature (PE\0\0)
    if (data[peOffset] == 0x50 && data[peOffset + 1] == 0x45 &&
        data[peOffset + 2] == 0x00 && data[peOffset + 3] == 0x00) {
        
        // Machine type at offset PE+4
        if (peOffset + 6 <= data.size()) {
            uint16_t machine = *reinterpret_cast<const uint16_t*>(&data[peOffset + 4]);
            
            if (machine == 0x014c) {
                info.architecture = "x86 (32-bit)";
            } else if (machine == 0x8664) {
                info.architecture = "x64 (64-bit)";
            } else {
                info.architecture = "Unknown";
            }
        }
        
        // Number of sections at PE+6
        if (peOffset + 8 <= data.size()) {
            info.numberOfSections = *reinterpret_cast<const uint16_t*>(&data[peOffset + 6]);
        }
        
        // Timestamp at PE+8
        if (peOffset + 12 <= data.size()) {
            info.timestamp = *reinterpret_cast<const uint32_t*>(&data[peOffset + 8]);
        }
        
        // Optional header starts at PE+24
        size_t optHeaderOffset = peOffset + 24;
        
        if (optHeaderOffset + 68 <= data.size()) {
            // Entry point at optional header + 16
            info.entryPoint = *reinterpret_cast<const uint32_t*>(&data[optHeaderOffset + 16]);
            
            // Image base at optional header + 28 (for PE32) or 24 (for PE32+)
            info.imageBase = *reinterpret_cast<const uint32_t*>(&data[optHeaderOffset + 28]);
            
            // Subsystem at optional header + 68
            uint16_t subsystem = *reinterpret_cast<const uint16_t*>(&data[optHeaderOffset + 68]);
            
            if (subsystem == 2) {
                info.subsystem = "GUI";
            } else if (subsystem == 3) {
                info.subsystem = "Console";
            } else {
                info.subsystem = "Other";
            }
        }
    }
    
    return info;
}

std::vector<std::string> PEParser::extractStrings(const std::vector<uint8_t>& data, size_t minLength) {
    std::vector<std::string> strings;
    std::string currentString;
    
    for (size_t i = 0; i < data.size(); i++) {
        if (isPrintable(data[i])) {
            currentString += static_cast<char>(data[i]);
        } else {
            if (currentString.length() >= minLength) {
                strings.push_back(currentString);
            }
            currentString.clear();
        }
    }
    
    // Don't forget the last string
    if (currentString.length() >= minLength) {
        strings.push_back(currentString);
    }
    
    return strings;
}

bool PEParser::isPrintable(uint8_t c) {
    return (c >= 0x20 && c <= 0x7E);
}
