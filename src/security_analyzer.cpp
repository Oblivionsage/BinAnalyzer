#include "security_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <sstream>

// PE Constants
#define IMAGE_SCN_MEM_READ                   0x40000000
#define IMAGE_SCN_MEM_WRITE                  0x80000000
#define IMAGE_SCN_MEM_EXECUTE                0x20000000
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE       0x0040
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT          0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_SEH             0x0400
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF           0x4000
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020

SecurityAnalyzer::SecurityAnalyzer() {
}

SecurityAnalysisResult SecurityAnalyzer::analyze(const std::vector<uint8_t>& data) {
    SecurityAnalysisResult result;
    result.securityScore = 0;
    
    if (data.size() < 64) return result;
    
    // Check if PE
    bool isPE = (data[0] == 0x4D && data[1] == 0x5A);
    if (!isPE) {
        result.threatAssessment = "Non-PE file";
        return result;
    }
    
    std::cout << "\033[93m[*] Analyzing security features...\033[0m\n";
    
    // Parse sections
    result.sections = parseSections(data);
    
    // Check security features
    result.features = checkSecurityFeatures(data);
    
    // Detect TLS callbacks
    result.tlsCallbacks = detectTLSCallbacks(data);
    
    // Detect code caves
    result.codeCaves = detectCodeCaves(data);
    
    // Calculate security score
    result.securityScore = calculateSecurityScore(result.features, result.sections);
    
    // Threat assessment
    if (result.securityScore >= 80) {
        result.threatAssessment = "Well Protected";
    } else if (result.securityScore >= 60) {
        result.threatAssessment = "Moderately Protected";
    } else if (result.securityScore >= 40) {
        result.threatAssessment = "Poorly Protected";
    } else {
        result.threatAssessment = "Highly Exploitable";
    }
    
    return result;
}

std::vector<SectionInfo> SecurityAnalyzer::parseSections(const std::vector<uint8_t>& data) {
    std::vector<SectionInfo> sections;
    
    if (data.size() < 0x400) return sections;
    
    // Get PE offset
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    if (peOffset + 0x100 > data.size()) return sections;
    
    // Check PE signature
    if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45) return sections;
    
    // Get number of sections
    uint16_t numberOfSections = *reinterpret_cast<const uint16_t*>(&data[peOffset + 6]);
    uint16_t sizeOfOptionalHeader = *reinterpret_cast<const uint16_t*>(&data[peOffset + 20]);
    
    // Section table starts after optional header
    size_t sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
    
    for (int i = 0; i < numberOfSections && sectionTableOffset + 40 <= data.size(); i++) {
        SectionInfo section;
        
        // Section name (8 bytes)
        char name[9] = {0};
        memcpy(name, &data[sectionTableOffset], 8);
        section.name = std::string(name);
        
        // Virtual size
        section.virtualSize = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 8]);
        
        // Virtual address
        section.virtualAddress = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 12]);
        
        // Raw size
        section.rawSize = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 16]);
        
        // Characteristics
        section.characteristics = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 36]);
        
        // Parse permissions
        section.isReadable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;
        section.isWritable = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        section.isExecutable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        section.isRWX = section.isReadable && section.isWritable && section.isExecutable;
        
        // Calculate entropy
        uint32_t rawOffset = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 20]);
        if (rawOffset > 0 && rawOffset < data.size() && section.rawSize > 0) {
            size_t sectionSize = std::min(static_cast<size_t>(section.rawSize), data.size() - rawOffset);
            section.entropy = calculateSectionEntropy(data, rawOffset, sectionSize);
        } else {
            section.entropy = 0.0;
        }
        
        sections.push_back(section);
        sectionTableOffset += 40; // Each section header is 40 bytes
    }
    
    return sections;
}

SecurityFeatures SecurityAnalyzer::checkSecurityFeatures(const std::vector<uint8_t>& data) {
    SecurityFeatures features = {false};
    
    if (data.size() < 0x200) return features;
    
    // Get PE offset
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    if (peOffset + 0x100 > data.size()) return features;
    
    // Optional header offset
    size_t optHeaderOffset = peOffset + 24;
    if (optHeaderOffset + 0x70 > data.size()) return features;
    
    // Get DllCharacteristics
    uint16_t dllCharacteristics = *reinterpret_cast<const uint16_t*>(&data[optHeaderOffset + 70]);
    
    // Check features
    features.dynamicBase = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    features.aslr = features.dynamicBase;
    
    features.nxCompat = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    features.dep = features.nxCompat;
    
    features.seh = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;
    features.safeSEH = features.seh;
    
    features.cfg = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    
    features.highEntropy = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    
    // GS detection (check for __security_cookie reference - simplified)
    features.gs = false; // Would need deeper analysis
    
    // Authenticode (check for certificate table - simplified)
    features.authenticode = false; // Would need to parse certificate directory
    
    return features;
}

std::vector<TLSCallback> SecurityAnalyzer::detectTLSCallbacks(const std::vector<uint8_t>& data) {
    std::vector<TLSCallback> callbacks;
    
    // TLS detection would require parsing TLS directory
    // This is a simplified placeholder
    
    return callbacks;
}

std::vector<CodeCave> SecurityAnalyzer::detectCodeCaves(const std::vector<uint8_t>& data) {
    std::vector<CodeCave> caves;
    
    // Look for sequences of null bytes (potential code caves)
    const size_t MIN_CAVE_SIZE = 100; // Minimum 100 bytes
    size_t nullCount = 0;
    size_t caveStart = 0;
    
    for (size_t i = 0; i < std::min(data.size(), static_cast<size_t>(1024 * 1024)); i++) {
        if (data[i] == 0x00) {
            if (nullCount == 0) {
                caveStart = i;
            }
            nullCount++;
        } else {
            if (nullCount >= MIN_CAVE_SIZE) {
                CodeCave cave;
                cave.offset = caveStart;
                cave.size = nullCount;
                cave.sectionName = "unknown"; // Would need section mapping
                caves.push_back(cave);
                
                if (caves.size() >= 10) break; // Limit to 10 caves
            }
            nullCount = 0;
        }
    }
    
    return caves;
}

double SecurityAnalyzer::calculateSectionEntropy(const std::vector<uint8_t>& data, size_t offset, size_t size) {
    if (size == 0 || offset + size > data.size()) return 0.0;
    
    int byteCounts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        byteCounts[data[offset + i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / size;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

int SecurityAnalyzer::calculateSecurityScore(const SecurityFeatures& features, const std::vector<SectionInfo>& sections) {
    int score = 0;
    
    // Security features scoring
    if (features.aslr) score += 20;
    if (features.dep) score += 20;
    if (features.cfg) score += 15;
    if (features.seh) score += 10;
    if (features.highEntropy) score += 10;
    if (features.gs) score += 10;
    if (features.authenticode) score += 15;
    
    // Penalty for RWX sections (MAJOR RED FLAG)
    for (const auto& section : sections) {
        if (section.isRWX) {
            score -= 30; // Heavy penalty
        }
    }
    
    // Ensure score is between 0-100
    return std::max(0, std::min(100, score));
}

void SecurityAnalyzer::displayResults(const SecurityAnalysisResult& result) {
    std::cout << "\n\033[1;96m╔═══════════════════════ SECURITY ANALYSIS ═══════════════════════╗\033[0m\n";
    
    // Overall assessment
    std::string assessmentColor;
    if (result.securityScore >= 80) assessmentColor = "\033[92m"; // Green
    else if (result.securityScore >= 60) assessmentColor = "\033[93m"; // Yellow
    else if (result.securityScore >= 40) assessmentColor = "\033[91m"; // Red
    else assessmentColor = "\033[95m"; // Magenta (critical)
    
    std::cout << "║ " << "\033[1mSecurity Score:\033[0m " << assessmentColor << result.securityScore << "/100\033[0m";
    std::cout << "  -  " << assessmentColor << result.threatAssessment << "\033[0m";
    
    size_t padding = 65 - (std::to_string(result.securityScore).length() + result.threatAssessment.length() + 10);
    if (padding > 0 && padding < 100) {
        for (size_t i = 0; i < padding; i++) std::cout << " ";
    }
    std::cout << "║\n";
    
    std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════════╣\033[0m\n";
    
    // Security Features
    std::cout << "║ \033[1mSecurity Features:\033[0m                                          ║\n";
    
    // Helper function to print features
    auto printFeature = [](const std::string& name, bool enabled) {
        std::cout << "║   " << (enabled ? "\033[92m✓\033[0m" : "\033[91m✗\033[0m") << " " << name;
        size_t len = name.length();
        if (len < 56) {
            for (size_t i = 0; i < (56 - len); i++) std::cout << " ";
        }
        std::cout << "║\n";
    };
    
    printFeature("ASLR (Address Space Layout Randomization)", result.features.aslr);
    printFeature("DEP/NX (Data Execution Prevention)", result.features.dep);
    printFeature("CFG (Control Flow Guard)", result.features.cfg);
    printFeature("SEH (Structured Exception Handling)", result.features.seh);
    printFeature("High Entropy ASLR (64-bit)", result.features.highEntropy);
    
    // Section Analysis
    if (!result.sections.empty()) {
        std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "║ \033[1mSection Analysis:\033[0m                                           ║\n";
        std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════════╣\033[0m\n";
        
        for (const auto& section : result.sections) {
            std::string perms;
            perms += section.isReadable ? "R" : "-";
            perms += section.isWritable ? "W" : "-";
            perms += section.isExecutable ? "X" : "-";
            
            std::string color = getSectionColor(section);
            
            std::cout << "║ " << color << std::left << std::setw(10) << section.name << "\033[0m";
            std::cout << "  " << perms << "  ";
            std::cout << "Entropy: " << std::fixed << std::setprecision(2) << section.entropy;
            
            if (section.isRWX) {
                std::cout << "  \033[95m[RWX!]\033[0m";
            } else if (section.isWritable && section.isExecutable) {
                std::cout << "  \033[91m[WX!]\033[0m";
            }
            
            // Simple padding
            std::cout << "     ║\n";
        }
    }
    
    // Code Caves
    if (!result.codeCaves.empty()) {
        std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "║ \033[1mCode Caves:\033[0m " << result.codeCaves.size() << " potential injection points";
        
        size_t caveCountLen = std::to_string(result.codeCaves.size()).length();
        padding = 40 - caveCountLen;
        if (padding > 0 && padding < 100) {
            for (size_t i = 0; i < padding; i++) std::cout << " ";
        }
        std::cout << "║\n";
        
        size_t displayCount = std::min(result.codeCaves.size(), static_cast<size_t>(5));
        for (size_t i = 0; i < displayCount; i++) {
            const auto& cave = result.codeCaves[i];
            std::cout << "║   0x" << std::hex << std::setfill('0') << std::setw(8) << cave.offset;
            std::cout << " - " << std::dec << cave.size << " bytes";
            std::cout << "                               ║\n";
        }
    }
    
    std::cout << "\033[1;96m╚═════════════════════════════════════════════════════════════════╝\033[0m\n";
}

std::string SecurityAnalyzer::getSectionColor(const SectionInfo& section) {
    if (section.isRWX) {
        return "\033[95m"; // Magenta - CRITICAL
    } else if (section.isWritable && section.isExecutable) {
        return "\033[91m"; // Red - HIGH RISK
    } else if (section.isExecutable) {
        return "\033[93m"; // Yellow
    } else if (section.isWritable) {
        return "\033[94m"; // Blue
    } else {
        return "\033[92m"; // Green
    }
}
