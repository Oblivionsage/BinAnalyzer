#ifndef SECURITY_ANALYZER_HPP
#define SECURITY_ANALYZER_HPP

#include <vector>
#include <string>
#include <cstdint>

struct SectionInfo {
    std::string name;
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawSize;
    uint32_t characteristics;
    bool isReadable;
    bool isWritable;
    bool isExecutable;
    bool isRWX;  // RED FLAG!
    double entropy;
};

struct SecurityFeatures {
    bool aslr;           // Address Space Layout Randomization
    bool dep;            // Data Execution Prevention (NX)
    bool seh;            // Structured Exception Handling
    bool cfg;            // Control Flow Guard
    bool gs;             // Stack Canary (/GS)
    bool authenticode;   // Digital Signature
    bool safeSEH;        // Safe Exception Handlers
    bool dynamicBase;    // Relocations
    bool nxCompat;       // NX Compatible
    bool highEntropy;    // High Entropy ASLR
};

struct TLSCallback {
    uint32_t address;
    bool present;
};

struct CodeCave {
    uint32_t offset;
    size_t size;
    std::string sectionName;
};

struct SecurityAnalysisResult {
    std::vector<SectionInfo> sections;
    SecurityFeatures features;
    std::vector<TLSCallback> tlsCallbacks;
    std::vector<CodeCave> codeCaves;
    int securityScore;  // 0-100
    std::string threatAssessment;
};

class SecurityAnalyzer {
public:
    SecurityAnalyzer();
    
    SecurityAnalysisResult analyze(const std::vector<uint8_t>& data);
    void displayResults(const SecurityAnalysisResult& result);
    
private:
    // PE parsing
    std::vector<SectionInfo> parseSections(const std::vector<uint8_t>& data);
    SecurityFeatures checkSecurityFeatures(const std::vector<uint8_t>& data);
    std::vector<TLSCallback> detectTLSCallbacks(const std::vector<uint8_t>& data);
    std::vector<CodeCave> detectCodeCaves(const std::vector<uint8_t>& data);
    
    // Utilities
    double calculateSectionEntropy(const std::vector<uint8_t>& data, size_t offset, size_t size);
    int calculateSecurityScore(const SecurityFeatures& features, const std::vector<SectionInfo>& sections);
    std::string getCharacteristicsString(uint32_t characteristics);
    std::string getSectionColor(const SectionInfo& section);
};

#endif // SECURITY_ANALYZER_HPP
