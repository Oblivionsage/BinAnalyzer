#ifndef STRING_ANALYZER_HPP
#define STRING_ANALYZER_HPP

#include <vector>
#include <string>
#include <map>
#include <cstdint>

enum class StringCategory {
    CRYPTO, ANTI_VM, ANTI_DEBUG, PERSISTENCE, MALWARE_API,
    DEBUGGING_TOOL, SANDBOX, RECONNAISSANCE,
    LATERAL_MOVEMENT, DATA_EXFILTRATION, BENIGN
};

struct SuspiciousString {
    std::string value;
    StringCategory category;
    uint32_t offset;
    double suspicionScore;
    std::string description;
};

struct StringAnalysisResult {
    std::vector<SuspiciousString> suspiciousStrings;
    std::map<StringCategory, int> categoryCounts;
    double overallSuspicionScore;
    bool highlyMalicious;
};

class StringAnalyzer {
public:
    StringAnalyzer();
    StringAnalysisResult analyze(const std::vector<uint8_t>& data);
    void displayResults(const StringAnalysisResult& result);

private:
    std::map<std::string, std::pair<StringCategory, double>> keywords_;
    
    void initializeKeywords();
    StringCategory categorizeString(const std::string& str, double& score);
    std::string getCategoryName(StringCategory category);
    std::string getCategoryColor(StringCategory category);
};

#endif
