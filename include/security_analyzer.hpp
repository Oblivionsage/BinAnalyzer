#ifndef SECURITY_ANALYZER_HPP
#define SECURITY_ANALYZER_HPP

#include <vector>
#include <string>
#include <cstdint>

struct SecurityFeatures {
    bool aslr;
    bool dep;
    bool seh;
    bool cfg;
    bool gs;
    bool authenticode;
    bool safeSEH;
    bool dynamicBase;
    bool nxCompat;
    bool highEntropy;
};

struct SectionInfo {
    std::string name;
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawSize;
    uint32_t characteristics;
    bool isReadable;
    bool isWritable;
    bool isExecutable;
    bool isRWX;
    double entropy;
};

struct TLSCallback {
    uint32_t address;
    std::string description;
};

struct CodeCave {
    uint32_t offset;
    size_t size;
    std::string sectionName;
};

struct SecurityAnalysisResult {
    SecurityFeatures features;
    std::vector<SectionInfo> sections;
    std::vector<TLSCallback> tlsCallbacks;
    std::vector<CodeCave> codeCaves;
    int securityScore;
    std::string threatAssessment;
};

class SecurityAnalyzer {
public:
    SecurityAnalyzer();
    
    SecurityAnalysisResult analyze(const std::vector<uint8_t>& data);
    void displayResults(const SecurityAnalysisResult& result);

private:
    std::vector<SectionInfo> parseSections(const std::vector<uint8_t>& data);
    SecurityFeatures checkSecurityFeatures(const std::vector<uint8_t>& data);
    std::vector<TLSCallback> detectTLSCallbacks(const std::vector<uint8_t>& data);
    std::vector<CodeCave> detectCodeCaves(const std::vector<uint8_t>& data);
    
    double calculateSectionEntropy(const std::vector<uint8_t>& data, size_t offset, size_t size);
    int calculateSecurityScore(const SecurityFeatures& features, const std::vector<SectionInfo>& sections);
    
    // Modern grid display helpers
    int getTerminalWidth();
    void displayProgressBar(const std::string& label, int value, int max, int width);
    std::string getScoreColor(int score);
    std::string getSectionColor(const SectionInfo& section);
    std::string padRight(const std::string& str, int width);
};

#endif // SECURITY_ANALYZER_HPP
