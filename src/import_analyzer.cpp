#include "import_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <set>
#include <cmath>

ImportAnalyzer::ImportAnalyzer() {
    initializeSuspiciousAPIsDB();
}

void ImportAnalyzer::initializeSuspiciousAPIsDB() {
    // Process Injection
    suspiciousAPIsDB["CreateRemoteThread"] = {ThreatLevel::CRITICAL, APICategory::PROCESS_INJECTION};
    suspiciousAPIsDB["WriteProcessMemory"] = {ThreatLevel::CRITICAL, APICategory::PROCESS_INJECTION};
    suspiciousAPIsDB["VirtualAllocEx"] = {ThreatLevel::HIGH, APICategory::PROCESS_INJECTION};
    suspiciousAPIsDB["SetThreadContext"] = {ThreatLevel::CRITICAL, APICategory::PROCESS_INJECTION};
    suspiciousAPIsDB["QueueUserAPC"] = {ThreatLevel::HIGH, APICategory::PROCESS_INJECTION};
    suspiciousAPIsDB["NtQueueApcThread"] = {ThreatLevel::CRITICAL, APICategory::PROCESS_INJECTION};
    suspiciousAPIsDB["RtlCreateUserThread"] = {ThreatLevel::CRITICAL, APICategory::PROCESS_INJECTION};
    
    // Memory Manipulation
    suspiciousAPIsDB["VirtualAlloc"] = {ThreatLevel::MEDIUM, APICategory::MEMORY_MANIPULATION};
    suspiciousAPIsDB["VirtualProtect"] = {ThreatLevel::HIGH, APICategory::MEMORY_MANIPULATION};
    suspiciousAPIsDB["VirtualProtectEx"] = {ThreatLevel::HIGH, APICategory::MEMORY_MANIPULATION};
    suspiciousAPIsDB["NtAllocateVirtualMemory"] = {ThreatLevel::HIGH, APICategory::MEMORY_MANIPULATION};
    suspiciousAPIsDB["NtProtectVirtualMemory"] = {ThreatLevel::HIGH, APICategory::MEMORY_MANIPULATION};
    
    // Anti-Debug
    suspiciousAPIsDB["IsDebuggerPresent"] = {ThreatLevel::MEDIUM, APICategory::ANTI_DEBUG};
    suspiciousAPIsDB["CheckRemoteDebuggerPresent"] = {ThreatLevel::MEDIUM, APICategory::ANTI_DEBUG};
    suspiciousAPIsDB["NtQueryInformationProcess"] = {ThreatLevel::HIGH, APICategory::ANTI_DEBUG};
    suspiciousAPIsDB["OutputDebugStringA"] = {ThreatLevel::LOW, APICategory::ANTI_DEBUG};
    suspiciousAPIsDB["OutputDebugStringW"] = {ThreatLevel::LOW, APICategory::ANTI_DEBUG};
    suspiciousAPIsDB["NtSetInformationThread"] = {ThreatLevel::HIGH, APICategory::ANTI_DEBUG};
    
    // Anti-VM
    suspiciousAPIsDB["SetupDiGetDeviceRegistryPropertyA"] = {ThreatLevel::MEDIUM, APICategory::ANTI_VM};
    suspiciousAPIsDB["GetSystemFirmwareTable"] = {ThreatLevel::MEDIUM, APICategory::ANTI_VM};
    
    // Network
    suspiciousAPIsDB["InternetOpenA"] = {ThreatLevel::MEDIUM, APICategory::NETWORK};
    suspiciousAPIsDB["InternetOpenW"] = {ThreatLevel::MEDIUM, APICategory::NETWORK};
    suspiciousAPIsDB["InternetOpenUrlA"] = {ThreatLevel::MEDIUM, APICategory::NETWORK};
    suspiciousAPIsDB["InternetOpenUrlW"] = {ThreatLevel::MEDIUM, APICategory::NETWORK};
    suspiciousAPIsDB["HttpOpenRequestA"] = {ThreatLevel::MEDIUM, APICategory::NETWORK};
    suspiciousAPIsDB["HttpSendRequestA"] = {ThreatLevel::MEDIUM, APICategory::NETWORK};
    suspiciousAPIsDB["WSAStartup"] = {ThreatLevel::LOW, APICategory::NETWORK};
    suspiciousAPIsDB["socket"] = {ThreatLevel::LOW, APICategory::NETWORK};
    suspiciousAPIsDB["connect"] = {ThreatLevel::MEDIUM, APICategory::NETWORK};
    suspiciousAPIsDB["send"] = {ThreatLevel::LOW, APICategory::NETWORK};
    suspiciousAPIsDB["recv"] = {ThreatLevel::LOW, APICategory::NETWORK};
    
    // File Operations
    suspiciousAPIsDB["CreateFileA"] = {ThreatLevel::LOW, APICategory::FILE_OPERATIONS};
    suspiciousAPIsDB["CreateFileW"] = {ThreatLevel::LOW, APICategory::FILE_OPERATIONS};
    suspiciousAPIsDB["WriteFile"] = {ThreatLevel::LOW, APICategory::FILE_OPERATIONS};
    suspiciousAPIsDB["DeleteFileA"] = {ThreatLevel::MEDIUM, APICategory::FILE_OPERATIONS};
    suspiciousAPIsDB["DeleteFileW"] = {ThreatLevel::MEDIUM, APICategory::FILE_OPERATIONS};
    suspiciousAPIsDB["MoveFileA"] = {ThreatLevel::LOW, APICategory::FILE_OPERATIONS};
    suspiciousAPIsDB["CopyFileA"] = {ThreatLevel::LOW, APICategory::FILE_OPERATIONS};
    
    // Registry
    suspiciousAPIsDB["RegOpenKeyA"] = {ThreatLevel::LOW, APICategory::REGISTRY};
    suspiciousAPIsDB["RegOpenKeyW"] = {ThreatLevel::LOW, APICategory::REGISTRY};
    suspiciousAPIsDB["RegSetValueA"] = {ThreatLevel::MEDIUM, APICategory::REGISTRY};
    suspiciousAPIsDB["RegSetValueW"] = {ThreatLevel::MEDIUM, APICategory::REGISTRY};
    suspiciousAPIsDB["RegSetValueExA"] = {ThreatLevel::MEDIUM, APICategory::REGISTRY};
    suspiciousAPIsDB["RegCreateKeyA"] = {ThreatLevel::MEDIUM, APICategory::REGISTRY};
    suspiciousAPIsDB["RegDeleteKeyA"] = {ThreatLevel::HIGH, APICategory::REGISTRY};
    
    // Crypto
    suspiciousAPIsDB["CryptEncrypt"] = {ThreatLevel::MEDIUM, APICategory::CRYPTO};
    suspiciousAPIsDB["CryptDecrypt"] = {ThreatLevel::MEDIUM, APICategory::CRYPTO};
    suspiciousAPIsDB["CryptAcquireContextA"] = {ThreatLevel::LOW, APICategory::CRYPTO};
    
    // Process Manipulation
    suspiciousAPIsDB["CreateProcessA"] = {ThreatLevel::MEDIUM, APICategory::PROCESS_MANIPULATION};
    suspiciousAPIsDB["CreateProcessW"] = {ThreatLevel::MEDIUM, APICategory::PROCESS_MANIPULATION};
    suspiciousAPIsDB["OpenProcess"] = {ThreatLevel::HIGH, APICategory::PROCESS_MANIPULATION};
    suspiciousAPIsDB["TerminateProcess"] = {ThreatLevel::HIGH, APICategory::PROCESS_MANIPULATION};
    suspiciousAPIsDB["SuspendThread"] = {ThreatLevel::MEDIUM, APICategory::PROCESS_MANIPULATION};
    suspiciousAPIsDB["ResumeThread"] = {ThreatLevel::MEDIUM, APICategory::PROCESS_MANIPULATION};
    
    // Privilege Escalation
    suspiciousAPIsDB["AdjustTokenPrivileges"] = {ThreatLevel::HIGH, APICategory::PRIVILEGE_ESCALATION};
    suspiciousAPIsDB["LookupPrivilegeValueA"] = {ThreatLevel::MEDIUM, APICategory::PRIVILEGE_ESCALATION};
    suspiciousAPIsDB["OpenProcessToken"] = {ThreatLevel::MEDIUM, APICategory::PRIVILEGE_ESCALATION};
    
    // Evasion
    suspiciousAPIsDB["Sleep"] = {ThreatLevel::LOW, APICategory::EVASION};
    suspiciousAPIsDB["GetTickCount"] = {ThreatLevel::LOW, APICategory::EVASION};
    suspiciousAPIsDB["NtDelayExecution"] = {ThreatLevel::MEDIUM, APICategory::EVASION};
    
    // Information Gathering
    suspiciousAPIsDB["GetComputerNameA"] = {ThreatLevel::LOW, APICategory::INFORMATION_GATHERING};
    suspiciousAPIsDB["GetUserNameA"] = {ThreatLevel::LOW, APICategory::INFORMATION_GATHERING};
    suspiciousAPIsDB["GetModuleHandleA"] = {ThreatLevel::LOW, APICategory::INFORMATION_GATHERING};
    suspiciousAPIsDB["GetProcAddress"] = {ThreatLevel::MEDIUM, APICategory::INFORMATION_GATHERING};
    suspiciousAPIsDB["LoadLibraryA"] = {ThreatLevel::MEDIUM, APICategory::INFORMATION_GATHERING};
    suspiciousAPIsDB["LoadLibraryW"] = {ThreatLevel::MEDIUM, APICategory::INFORMATION_GATHERING};
}

std::vector<ImportFunction> ImportAnalyzer::parseImportTable(const std::vector<uint8_t>& data) {
    std::vector<ImportFunction> imports;
    
    if (data.size() < 64) return imports;
    
    // Check MZ signature
    if (data[0] != 0x4D || data[1] != 0x5A) return imports;
    
    // Get PE offset
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    if (peOffset + 4 > data.size()) return imports;
    
    // Check PE signature
    if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45) return imports;
    
    // Get optional header offset
    size_t optHeaderOffset = peOffset + 24;
    if (optHeaderOffset + 96 > data.size()) return imports;
    
    // Get import directory RVA (data directory[1])
    uint32_t importDirRVA = *reinterpret_cast<const uint32_t*>(&data[optHeaderOffset + 104]);
    
    if (importDirRVA == 0) return imports;
    
    // size_t importDirOffset = importDirRVA;
    // TODO: Implement proper RVA to file offset conversion using section table
    
    return imports;
}

ImportAnalysisResult ImportAnalyzer::analyze(const std::vector<uint8_t>& data) {
    ImportAnalysisResult result;
    result.totalImports = 0;
    result.suspiciousCount = 0;
    result.overallThreat = ThreatLevel::INFO;
    
    if (data.size() < 64) return result;
    
    // Detect file type first
    bool isPE = (data[0] == 0x4D && data[1] == 0x5A);
    // bool isELF = (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46);
    // Currently only analyzing PE files to avoid false positives
    
    // Only analyze PE files
    if (!isPE) {
        return result;
    }
    
    std::cout << "\033[93m[*] Analyzing suspicious APIs... (this may take a moment for large files)\033[0m\n";
    
    // OPTIMIZATION: Only scan first 2MB or entire file (whichever is smaller)
    size_t scanSize = std::min(data.size(), static_cast<size_t>(2 * 1024 * 1024));
    
    std::string currentString;
    std::set<std::string> foundAPIs; // Use set to avoid duplicates
    const size_t MAX_SUSPICIOUS_APIS = 50; // Limit results
    
    for (size_t i = 0; i < scanSize && result.suspiciousCount < MAX_SUSPICIOUS_APIS; i++) {
        uint8_t byte = data[i];
        
        if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9')) {
            currentString += static_cast<char>(byte);
            
            // Limit string length to avoid memory issues
            if (currentString.length() > 100) {
                currentString.clear();
            }
        } else {
            if (currentString.length() >= 4 && currentString.length() <= 50) {
                ThreatLevel threat;
                APICategory category;
                
                if (isSuspiciousAPI(currentString, threat, category)) {
                    // Check if not already found (using set)
                    if (foundAPIs.find(currentString) == foundAPIs.end()) {
                        foundAPIs.insert(currentString);
                        
                        ImportFunction func;
                        func.name = currentString;
                        func.dll = "unknown";
                        func.threat = threat;
                        func.category = category;
                        
                        result.suspiciousAPIs.push_back(func);
                        result.categoryCount[category]++;
                        result.suspiciousCount++;
                        
                        if (static_cast<int>(threat) > static_cast<int>(result.overallThreat)) {
                            result.overallThreat = threat;
                        }
                    }
                }
            }
            currentString.clear();
        }
        
        // Progress indicator for very large files
        if (i % 100000 == 0 && i > 0) {
            std::cout << "\r\033[93m[*] Scanned " << (i / 1024) << " KB...\033[0m" << std::flush;
        }
    }
    
    if (scanSize < data.size()) {
        std::cout << "\n\033[93m[!] Note: Only first 2MB scanned for performance\033[0m\n";
    }
    
    return result;
}

bool ImportAnalyzer::isSuspiciousAPI(const std::string& apiName, ThreatLevel& threat, APICategory& category) {
    auto it = suspiciousAPIsDB.find(apiName);
    if (it != suspiciousAPIsDB.end()) {
        threat = it->second.first;
        category = it->second.second;
        return true;
    }
    return false;
}

void ImportAnalyzer::displayResults(const ImportAnalysisResult& result) {
    std::cout << "\n[*] Import Table Analysis\n";
    std::cout << "-------------------------\n";
    
    std::string threatColor;
    if (result.overallThreat == ThreatLevel::CRITICAL) threatColor = "\033[91m";
    else if (result.overallThreat == ThreatLevel::HIGH) threatColor = "\033[91m";
    else if (result.overallThreat == ThreatLevel::MEDIUM) threatColor = "\033[93m";
    else threatColor = "\033[92m";
    
    std::cout << "Threat level: " << threatColor << getThreatLevelString(result.overallThreat) << "\033[0m\n";
    std::cout << "Suspicious APIs: " << result.suspiciousCount << "\n\n";
    
    if (!result.categoryCount.empty()) {
        std::cout << "Categories:\n";
        for (const auto& cat : result.categoryCount) {
            std::cout << "  " << getCategoryString(cat.first) << ": " << cat.second << "\n";
        }
        std::cout << "\n";
    }
    
    if (!result.suspiciousAPIs.empty()) {
        std::cout << "Detected APIs:\n";
        size_t displayCount = std::min(result.suspiciousAPIs.size(), static_cast<size_t>(15));
        for (size_t i = 0; i < displayCount; i++) {
            const auto& api = result.suspiciousAPIs[i];
            std::cout << "  \033[93m" << api.name << "\033[0m";
            std::cout << " (" << getCategoryString(api.category) << ")\n";
        }
        
        if (result.suspiciousAPIs.size() > displayCount) {
            std::cout << "  ... and " << (result.suspiciousAPIs.size() - displayCount) << " more\n";
        }
    }
    std::cout << "\n";
}

std::string ImportAnalyzer::getThreatLevelString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::INFO: return "INFO";
        case ThreatLevel::LOW: return "LOW";
        case ThreatLevel::MEDIUM: return "MEDIUM";
        case ThreatLevel::HIGH: return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string ImportAnalyzer::getThreatLevelColor(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::INFO: return "\033[94m";      // Blue
        case ThreatLevel::LOW: return "\033[92m";       // Green
        case ThreatLevel::MEDIUM: return "\033[93m";    // Yellow
        case ThreatLevel::HIGH: return "\033[91m";      // Red
        case ThreatLevel::CRITICAL: return "\033[95m";  // Magenta
        default: return "\033[0m";
    }
}

std::string ImportAnalyzer::getCategoryString(APICategory category) {
    switch (category) {
        case APICategory::PROCESS_INJECTION: return "Process Injection";
        case APICategory::MEMORY_MANIPULATION: return "Memory Manipulation";
        case APICategory::ANTI_DEBUG: return "Anti-Debug";
        case APICategory::ANTI_VM: return "Anti-VM";
        case APICategory::NETWORK: return "Network Operations";
        case APICategory::FILE_OPERATIONS: return "File Operations";
        case APICategory::REGISTRY: return "Registry Operations";
        case APICategory::CRYPTO: return "Cryptography";
        case APICategory::PROCESS_MANIPULATION: return "Process Manipulation";
        case APICategory::PRIVILEGE_ESCALATION: return "Privilege Escalation";
        case APICategory::EVASION: return "Evasion Techniques";
        case APICategory::INFORMATION_GATHERING: return "Information Gathering";
        default: return "Unknown";
    }
}

std::string ImportAnalyzer::getCategoryColor(APICategory category) {
    switch (category) {
        case APICategory::PROCESS_INJECTION: return "\033[95m";      // Magenta
        case APICategory::MEMORY_MANIPULATION: return "\033[91m";    // Red
        case APICategory::ANTI_DEBUG: return "\033[93m";             // Yellow
        case APICategory::ANTI_VM: return "\033[93m";                // Yellow
        case APICategory::NETWORK: return "\033[94m";                // Blue
        case APICategory::FILE_OPERATIONS: return "\033[96m";        // Cyan
        case APICategory::REGISTRY: return "\033[96m";               // Cyan
        case APICategory::CRYPTO: return "\033[92m";                 // Green
        case APICategory::PROCESS_MANIPULATION: return "\033[91m";   // Red
        case APICategory::PRIVILEGE_ESCALATION: return "\033[95m";   // Magenta
        case APICategory::EVASION: return "\033[93m";                // Yellow
        case APICategory::INFORMATION_GATHERING: return "\033[94m";  // Blue
        default: return "\033[0m";
    }
}
