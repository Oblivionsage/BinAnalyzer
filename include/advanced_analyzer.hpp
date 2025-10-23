#ifndef ADVANCED_ANALYZER_HPP
#define ADVANCED_ANALYZER_HPP

#include <vector>
#include <string>
#include <map>
#include <set>
#include <cstdint>

// ============================================================================
// PACKER DETECTION
// ============================================================================

enum class PackerType {
    NONE,
    UPX,
    THEMIDA,
    VMPROTECT,
    ASPACK,
    ARMADILLO,
    PECOMPACT,
    PETITE,
    FSG,
    NSPACK,
    MPRESS,
    GENERIC_PACKER,
    UNKNOWN_PACKER
};

struct PackerSignature {
    std::string name;
    std::vector<std::string> sectionNames;
    std::vector<std::vector<uint8_t>> entryPointSignatures;
    double minEntropy;
    bool hasAnomalousEP;
    bool hasLowImportCount;
};

struct PackerDetectionResult {
    PackerType type;
    std::string name;
    double confidence; // 0.0 - 1.0
    std::vector<std::string> indicators;
    bool isPacked;
    double suspiciousEntropy;
    bool entryPointAnomaly;
    int importCount;
};

// ============================================================================
// SHELLCODE DETECTION
// ============================================================================

enum class ShellcodeType {
    NONE,
    NOP_SLED,
    EGG_HUNTER,
    GETPC_CALL,
    GETPC_FNSTENV,
    METASPLOIT_PATTERN,
    REVERSE_SHELL,
    BIND_SHELL,
    SUSPICIOUS_SEQUENCE,
    UNKNOWN
};

struct ShellcodePattern {
    ShellcodeType type;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> mask; // 0xFF = must match, 0x00 = wildcard
    std::string description;
};

struct ShellcodeDetection {
    ShellcodeType type;
    uint32_t offset;
    size_t length;
    std::string description;
    double confidence;
};

struct ShellcodeAnalysisResult {
    std::vector<ShellcodeDetection> detections;
    bool shellcodeFound;
    int totalPatterns;
};

// ============================================================================
// NETWORK IOC EXTRACTION
// ============================================================================

enum class IOCType { // i just changed because building fails at macOS
    IPV4_ADDRESS,
    IPV6_ADDRESS,
    URL_ADDRESS,
    DOMAIN_NAME,
    EMAIL_ADDRESS,
    BITCOIN_ADDRESS
};

struct NetworkIOC {
    IOCType type;
    std::string value;
    uint32_t offset;
    std::string context; // Surrounding text for context
};

struct IOCExtractionResult {
    std::vector<NetworkIOC> iocs;
    std::map<IOCType, int> counts;
    bool networkActivitySuspected;
};

// ============================================================================
// SUSPICIOUS STRINGS ANALYSIS
// ============================================================================

enum class StringCategory {
    CRYPTO,
    ANTI_VM,
    ANTI_DEBUG,
    PERSISTENCE,
    MALWARE_API,
    DEBUGGING_TOOL,
    SANDBOX,
    RECONNAISSANCE,
    LATERAL_MOVEMENT,
    DATA_EXFILTRATION,
    BENIGN
};

struct SuspiciousString {
    std::string value;
    StringCategory category;
    uint32_t offset;
    double suspicionScore; // 0.0 - 1.0
    std::string description;
};

struct StringAnalysisResult {
    std::vector<SuspiciousString> suspiciousStrings;
    std::map<StringCategory, int> categoryCounts;
    double overallSuspicionScore;
    bool highlyMalicious;
};

// ============================================================================
// ADVANCED ANALYZER (Main Class)
// ============================================================================

class AdvancedAnalyzer {
public:
    AdvancedAnalyzer();
    
    // Main analysis functions
    PackerDetectionResult detectPacker(const std::vector<uint8_t>& data);
    ShellcodeAnalysisResult detectShellcode(const std::vector<uint8_t>& data);
    IOCExtractionResult extractIOCs(const std::vector<uint8_t>& data);
    StringAnalysisResult analyzeSuspiciousStrings(const std::vector<uint8_t>& data);
    
    // Display functions
    void displayPackerResults(const PackerDetectionResult& result);
    void displayShellcodeResults(const ShellcodeAnalysisResult& result);
    void displayIOCResults(const IOCExtractionResult& result);
    void displayStringResults(const StringAnalysisResult& result);
    
private:
    // Packer detection helpers
    std::vector<PackerSignature> packerSignatures_;
    void initializePackerSignatures();
    PackerType identifyPackerBySection(const std::vector<std::string>& sectionNames);
    bool checkEntryPointAnomaly(const std::vector<uint8_t>& data);
    double calculateMaxSectionEntropy(const std::vector<uint8_t>& data);
    int countImports(const std::vector<uint8_t>& data);
    
    // Shellcode detection helpers
    std::vector<ShellcodePattern> shellcodePatterns_;
    void initializeShellcodePatterns();
    bool matchPattern(const std::vector<uint8_t>& data, size_t offset, 
                      const std::vector<uint8_t>& pattern, 
                      const std::vector<uint8_t>& mask);
    bool detectNOPSled(const std::vector<uint8_t>& data, size_t offset);
    
    // IOC extraction helpers
    bool isValidIPv4(const std::string& str);
    bool isValidDomain(const std::string& str);
    bool isValidEmail(const std::string& str);
    std::string extractContext(const std::vector<uint8_t>& data, size_t offset, size_t length);
    
    // String analysis helpers
    std::map<std::string, std::pair<StringCategory, double>> suspiciousKeywords_;
    void initializeSuspiciousKeywords();
    StringCategory categorizeString(const std::string& str, double& score);
    
    // Utility functions
    std::string getPackerName(PackerType type);
    std::string getShellcodeTypeName(ShellcodeType type);
    std::string getIOCTypeName(IOCType type);
    std::string getCategoryName(StringCategory category);
    std::string getCategoryColor(StringCategory category);
};

#endif // ADVANCED_ANALYZER_HPP
