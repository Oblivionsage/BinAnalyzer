#ifndef PACKER_DETECTOR_HPP
#define PACKER_DETECTOR_HPP

#include <vector>
#include <string>
#include <cstdint>

enum class PackerType {
    NONE, UPX, THEMIDA, VMPROTECT, ASPACK, ARMADILLO,
    PECOMPACT, MPRESS, GENERIC_PACKER, UNKNOWN_PACKER
};

struct PackerSignature {
    std::string name;
    std::vector<std::string> sectionNames;
    double minEntropy;
    bool hasAnomalousEP;
    bool hasLowImportCount;
};

struct PackerDetectionResult {
    PackerType type;
    std::string name;
    double confidence;
    std::vector<std::string> indicators;
    bool isPacked;
    double suspiciousEntropy;
    bool entryPointAnomaly;
    int importCount;
};

class PackerDetector {
public:
    PackerDetector();
    PackerDetectionResult detect(const std::vector<uint8_t>& data);
    void displayResults(const PackerDetectionResult& result);

private:
    std::vector<PackerSignature> signatures_;
    
    void initializeSignatures();
    PackerType identifyBySection(const std::vector<std::string>& sections);
    double calculateEntropy(const std::vector<uint8_t>& data);
    std::string getPackerName(PackerType type);
};

#endif
