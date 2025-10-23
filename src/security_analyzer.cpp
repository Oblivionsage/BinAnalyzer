#include "security_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <sys/ioctl.h>
#include <unistd.h>

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
    
    bool isPE = (data[0] == 0x4D && data[1] == 0x5A);
    if (!isPE) {
        result.threatAssessment = "Non-PE file";
        return result;
    }
    
    std::cout << "\033[93m[*] Analyzing security features...\033[0m\n";
    
    result.sections = parseSections(data);
    result.features = checkSecurityFeatures(data);
    result.tlsCallbacks = detectTLSCallbacks(data);
    result.codeCaves = detectCodeCaves(data);
    result.securityScore = calculateSecurityScore(result.features, result.sections);
    
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
    
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    if (peOffset + 0x100 > data.size()) return sections;
    
    if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45) return sections;
    
    uint16_t numberOfSections = *reinterpret_cast<const uint16_t*>(&data[peOffset + 6]);
    uint16_t sizeOfOptionalHeader = *reinterpret_cast<const uint16_t*>(&data[peOffset + 20]);
    
    size_t sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
    
    for (int i = 0; i < numberOfSections && sectionTableOffset + 40 <= data.size(); i++) {
        SectionInfo section;
        
        char name[9] = {0};
        memcpy(name, &data[sectionTableOffset], 8);
        section.name = std::string(name);
        
        section.virtualSize = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 8]);
        section.virtualAddress = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 12]);
        section.rawSize = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 16]);
        section.characteristics = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 36]);
        
        section.isReadable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;
        section.isWritable = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        section.isExecutable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        section.isRWX = section.isReadable && section.isWritable && section.isExecutable;
        
        uint32_t rawOffset = *reinterpret_cast<const uint32_t*>(&data[sectionTableOffset + 20]);
        if (rawOffset > 0 && rawOffset < data.size() && section.rawSize > 0) {
            size_t sectionSize = std::min(static_cast<size_t>(section.rawSize), data.size() - rawOffset);
            section.entropy = calculateSectionEntropy(data, rawOffset, sectionSize);
        } else {
            section.entropy = 0.0;
        }
        
        sections.push_back(section);
        sectionTableOffset += 40;
    }
    
    return sections;
}

SecurityFeatures SecurityAnalyzer::checkSecurityFeatures(const std::vector<uint8_t>& data) {
    SecurityFeatures features = {false};
    
    if (data.size() < 0x200) return features;
    
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    if (peOffset + 0x100 > data.size()) return features;
    
    size_t optHeaderOffset = peOffset + 24;
    if (optHeaderOffset + 0x70 > data.size()) return features;
    
    uint16_t dllCharacteristics = *reinterpret_cast<const uint16_t*>(&data[optHeaderOffset + 70]);
    
    features.dynamicBase = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    features.aslr = features.dynamicBase;
    
    features.nxCompat = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    features.dep = features.nxCompat;
    
    features.seh = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;
    features.safeSEH = features.seh;
    
    features.cfg = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    
    features.highEntropy = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    
    features.gs = false;
    features.authenticode = false;
    
    return features;
}

std::vector<TLSCallback> SecurityAnalyzer::detectTLSCallbacks(const std::vector<uint8_t>& data) {
    std::vector<TLSCallback> callbacks;
    return callbacks;
}

std::vector<CodeCave> SecurityAnalyzer::detectCodeCaves(const std::vector<uint8_t>& data) {
    std::vector<CodeCave> caves;
    
    const size_t MIN_CAVE_SIZE = 100;
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
                cave.sectionName = "unknown";
                caves.push_back(cave);
                
                if (caves.size() >= 10) break;
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
    
    if (features.aslr) score += 20;
    if (features.dep) score += 20;
    if (features.cfg) score += 15;
    if (features.seh) score += 10;
    if (features.highEntropy) score += 10;
    if (features.gs) score += 10;
    if (features.authenticode) score += 15;
    
    for (const auto& section : sections) {
        if (section.isRWX) {
            score -= 30;
        }
    }
    
    return std::max(0, std::min(100, score));
}

// ============================================================================
// MODERN GRID DISPLAY - HELPER FUNCTIONS
// ============================================================================

int SecurityAnalyzer::getTerminalWidth() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    int width = w.ws_col;
    return (width > 0 && width < 300) ? width : 120;
}

void SecurityAnalyzer::displayProgressBar(const std::string& label, int value, int max, int width) {
    if (!label.empty()) {
        std::cout << label << " ";
    }
    
    int filled = (value * width) / max;
    std::string color;
    
    if (value >= 80) color = "\033[92m";
    else if (value >= 60) color = "\033[93m";
    else if (value >= 40) color = "\033[91m";
    else color = "\033[95m";
    
    std::cout << "[" << color;
    for (int i = 0; i < width; i++) {
        std::cout << (i < filled ? "█" : "░");
    }
    std::cout << "\033[0m] " << value << "%";
}

std::string SecurityAnalyzer::getScoreColor(int score) {
    if (score >= 80) return "\033[92m";
    else if (score >= 60) return "\033[93m";
    else if (score >= 40) return "\033[91m";
    else return "\033[95m";
}

std::string SecurityAnalyzer::getSectionColor(const SectionInfo& section) {
    if (section.isRWX) {
        return "\033[95m";
    } else if (section.isWritable && section.isExecutable) {
        return "\033[91m";
    } else if (section.isExecutable) {
        return "\033[93m";
    } else if (section.isWritable) {
        return "\033[94m";
    } else {
        return "\033[92m";
    }
}

std::string SecurityAnalyzer::padRight(const std::string& str, int width) {
    int visibleLen = 0;
    bool inEscape = false;
    for (char c : str) {
        if (c == '\033') inEscape = true;
        else if (inEscape && c == 'm') inEscape = false;
        else if (!inEscape) visibleLen++;
    }
    
    int padding = width - visibleLen;
    if (padding > 0) {
        return str + std::string(padding, ' ');
    }
    return str;
}

void SecurityAnalyzer::displayResults(const SecurityAnalysisResult& result) {
    std::cout << "\n[*] Security Analysis\n";
    std::cout << "---------------------\n";
    
    // Score
    std::string scoreColor = getScoreColor(result.securityScore);
    std::cout << "Security score: " << scoreColor << result.securityScore << "/100\033[0m";
    std::cout << " (" << result.threatAssessment << ")\n\n";
    
    // Features
    std::cout << "Security features:\n";
    std::cout << "  ASLR:       " << (result.features.aslr ? "\033[92menabled\033[0m" : "\033[91mdisabled\033[0m") << "\n";
    std::cout << "  DEP/NX:     " << (result.features.dep ? "\033[92menabled\033[0m" : "\033[91mdisabled\033[0m") << "\n";
    std::cout << "  CFG:        " << (result.features.cfg ? "\033[92menabled\033[0m" : "\033[91mdisabled\033[0m") << "\n";
    std::cout << "  SafeSEH:    " << (result.features.seh ? "\033[92menabled\033[0m" : "\033[91mdisabled\033[0m") << "\n";
    std::cout << "  High ASLR:  " << (result.features.highEntropy ? "\033[92menabled\033[0m" : "\033[91mdisabled\033[0m") << "\n";
    std::cout << "\n";
    
    // Sections
    if (!result.sections.empty()) {
        std::cout << "Sections:\n";
        std::cout << "  Name      Perms  Entropy\n";
        std::cout << "  --------  -----  -------\n";
        
        for (const auto& section : result.sections) {
            std::string perms;
            perms += section.isReadable ? "R" : "-";
            perms += section.isWritable ? "W" : "-";
            perms += section.isExecutable ? "X" : "-";
            
            std::string color = "";
            if (section.isRWX) color = "\033[95m";
            else if (section.isWritable && section.isExecutable) color = "\033[91m";
            else if (section.entropy > 7.0) color = "\033[93m";
            
            std::cout << "  " << color << std::left << std::setw(8) << section.name 
                      << "  " << perms << "    " 
                      << std::fixed << std::setprecision(2) << section.entropy;
            
            if (section.isRWX) std::cout << "  [RWX!]";
            std::cout << "\033[0m\n";
        }
        std::cout << "\n";
    }
    
    // Code caves
    if (!result.codeCaves.empty()) {
        std::cout << "Code caves: " << result.codeCaves.size() << " found\n";
        for (size_t i = 0; i < std::min(result.codeCaves.size(), static_cast<size_t>(3)); i++) {
            std::cout << "  \033[96m0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << result.codeCaves[i].offset << "\033[0m" << std::dec 
                      << "  (" << result.codeCaves[i].size << " bytes)\n";
        }
    }
}
