#ifndef IMPORT_ANALYZER_HPP
#define IMPORT_ANALYZER_HPP

#include <vector>
#include <string>
#include <map>
#include <cstdint>

enum class ThreatLevel {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class APICategory {
    PROCESS_INJECTION,
    MEMORY_MANIPULATION,
    ANTI_DEBUG,
    ANTI_VM,
    NETWORK,
    FILE_OPERATIONS,
    REGISTRY,
    CRYPTO,
    PROCESS_MANIPULATION,
    PRIVILEGE_ESCALATION,
    EVASION,
    INFORMATION_GATHERING,
    BENIGN
};

struct ImportFunction {
    std::string name;
    std::string dll;
    ThreatLevel threat;
    APICategory category;
    std::string description;
};

struct ImportAnalysisResult {
    std::vector<ImportFunction> suspiciousAPIs;
    std::map<APICategory, int> categoryCount;
    ThreatLevel overallThreat;
    int totalImports;
    int suspiciousCount;
};

class ImportAnalyzer {
public:
    ImportAnalyzer();
    
    ImportAnalysisResult analyze(const std::vector<uint8_t>& data);
    void displayResults(const ImportAnalysisResult& result);
    
private:
    std::map<std::string, std::pair<ThreatLevel, APICategory>> suspiciousAPIsDB;
    
    void initializeSuspiciousAPIsDB();
    bool isSuspiciousAPI(const std::string& apiName, ThreatLevel& threat, APICategory& category);
    std::string getThreatLevelString(ThreatLevel level);
    std::string getThreatLevelColor(ThreatLevel level);
    std::string getCategoryString(APICategory category);
    std::string getCategoryColor(APICategory category);
    
    // PE parsing helpers
    std::vector<ImportFunction> parseImportTable(const std::vector<uint8_t>& data);
};

#endif // IMPORT_ANALYZER_HPP
