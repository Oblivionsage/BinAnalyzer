#include "string_analyzer.hpp"
#include <iostream>
#include <algorithm>

StringAnalyzer::StringAnalyzer() {
    initializeKeywords();
}

void StringAnalyzer::initializeKeywords() {
    // Cryptography
    keywords_["AES"] = {StringCategory::CRYPTO, 0.6};
    keywords_["RC4"] = {StringCategory::CRYPTO, 0.7};
    keywords_["XOR"] = {StringCategory::CRYPTO, 0.5};
    keywords_["Base64"] = {StringCategory::CRYPTO, 0.4};
    keywords_["encrypt"] = {StringCategory::CRYPTO, 0.6};
    keywords_["decrypt"] = {StringCategory::CRYPTO, 0.6};
    keywords_["CryptEncrypt"] = {StringCategory::CRYPTO, 0.7};
    keywords_["CryptDecrypt"] = {StringCategory::CRYPTO, 0.7};
    
    // Anti-VM
    keywords_["VMware"] = {StringCategory::ANTI_VM, 0.8};
    keywords_["VirtualBox"] = {StringCategory::ANTI_VM, 0.8};
    keywords_["VBOX"] = {StringCategory::ANTI_VM, 0.8};
    keywords_["QEMU"] = {StringCategory::ANTI_VM, 0.8};
    keywords_["Hyper-V"] = {StringCategory::ANTI_VM, 0.7};
    
    // Anti-Debug
    keywords_["IsDebuggerPresent"] = {StringCategory::ANTI_DEBUG, 0.9};
    keywords_["CheckRemoteDebuggerPresent"] = {StringCategory::ANTI_DEBUG, 0.9};
    keywords_["OutputDebugString"] = {StringCategory::ANTI_DEBUG, 0.7};
    keywords_["NtQueryInformationProcess"] = {StringCategory::ANTI_DEBUG, 0.8};
    
    // Persistence
    keywords_["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"] = {StringCategory::PERSISTENCE, 0.8};
    keywords_["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"] = {StringCategory::PERSISTENCE, 0.9};
    keywords_["schtasks"] = {StringCategory::PERSISTENCE, 0.7};
    
    // Debugging Tools
    keywords_["OllyDbg"] = {StringCategory::DEBUGGING_TOOL, 0.7};
    keywords_["IDA"] = {StringCategory::DEBUGGING_TOOL, 0.6};
    keywords_["x64dbg"] = {StringCategory::DEBUGGING_TOOL, 0.7};
    
    // Sandbox
    keywords_["Sandbox"] = {StringCategory::SANDBOX, 0.8};
    keywords_["Cuckoo"] = {StringCategory::SANDBOX, 0.8};
    
    // Reconnaissance
    keywords_["ipconfig"] = {StringCategory::RECONNAISSANCE, 0.6};
    keywords_["whoami"] = {StringCategory::RECONNAISSANCE, 0.6};
    keywords_["systeminfo"] = {StringCategory::RECONNAISSANCE, 0.7};
    
    // Lateral Movement
    keywords_["psexec"] = {StringCategory::LATERAL_MOVEMENT, 0.9};
    keywords_["net use"] = {StringCategory::LATERAL_MOVEMENT, 0.7};
    
    // Malware APIs
    keywords_["CreateRemoteThread"] = {StringCategory::MALWARE_API, 0.9};
    keywords_["VirtualAllocEx"] = {StringCategory::MALWARE_API, 0.8};
    keywords_["WriteProcessMemory"] = {StringCategory::MALWARE_API, 0.9};
}

StringAnalysisResult StringAnalyzer::analyze(const std::vector<uint8_t>& data) {
    StringAnalysisResult result;
    result.overallSuspicionScore = 0.0;
    result.highlyMalicious = false;
    
    std::cout << "\033[93m[*] Analyzing suspicious strings...\033[0m\n";
    
    std::string currentString;
    size_t stringStart = 0;
    
    for (size_t i = 0; i < std::min(data.size(), static_cast<size_t>(2 * 1024 * 1024)); i++) {
        uint8_t byte = data[i];
        
        if (byte >= 0x20 && byte <= 0x7E) {
            if (currentString.empty()) stringStart = i;
            currentString += static_cast<char>(byte);
        } else {
            if (currentString.length() >= 4) {
                double score = 0.0;
                StringCategory category = categorizeString(currentString, score);
                
                if (category != StringCategory::BENIGN && score > 0.3) {
                    SuspiciousString suspicious;
                    suspicious.value = currentString;
                    suspicious.category = category;
                    suspicious.offset = stringStart;
                    suspicious.suspicionScore = score;
                    suspicious.description = getCategoryName(category);
                    
                    result.suspiciousStrings.push_back(suspicious);
                    result.categoryCounts[category]++;
                    
                    if (result.suspiciousStrings.size() >= 50) break;
                }
            }
            currentString.clear();
        }
    }
    
    if (!result.suspiciousStrings.empty()) {
        double totalScore = 0.0;
        for (const auto& str : result.suspiciousStrings) totalScore += str.suspicionScore;
        result.overallSuspicionScore = totalScore / result.suspiciousStrings.size();
        result.highlyMalicious = (result.overallSuspicionScore > 0.7);
    }
    
    return result;
}

StringCategory StringAnalyzer::categorizeString(const std::string& str, double& score) {
    score = 0.0;
    StringCategory bestCategory = StringCategory::BENIGN;
    
    for (const auto& keyword : keywords_) {
        if (str.find(keyword.first) != std::string::npos) {
            if (keyword.second.second > score) {
                score = keyword.second.second;
                bestCategory = keyword.second.first;
            }
        }
    }
    return bestCategory;
}

void StringAnalyzer::displayResults(const StringAnalysisResult& result) {
    if (result.suspiciousStrings.empty()) return;
    
    std::cout << "\n[*] Suspicious Strings\n";
    std::cout << "----------------------\n";
    
    int score = static_cast<int>(result.overallSuspicionScore * 100);
    std::string scoreColor = (score >= 70) ? "\033[91m" : (score >= 50) ? "\033[93m" : "\033[92m";
    std::cout << "Threat level: " << scoreColor << score << "%\033[0m\n";
    std::cout << "Total found: " << result.suspiciousStrings.size() << "\n\n";
    
    std::cout << "Categories:\n";
    for (const auto& cat : result.categoryCounts) {
        std::cout << "  " << getCategoryName(cat.first) << ": " << cat.second << "\n";
    }
    std::cout << "\n";
    
    std::cout << "Top findings:\n";
    size_t displayCount = std::min(result.suspiciousStrings.size(), static_cast<size_t>(8));
    for (size_t i = 0; i < displayCount; i++) {
        const auto& str = result.suspiciousStrings[i];
        std::string value = str.value;
        if (value.length() > 60) value = value.substr(0, 57) + "...";
        std::cout << "  " << value << "\n";
    }
    
    if (result.suspiciousStrings.size() > displayCount) {
        std::cout << "  ... and " << (result.suspiciousStrings.size() - displayCount) << " more\n";
    }
    std::cout << "\n";
}

std::string StringAnalyzer::getCategoryName(StringCategory category) {
    switch (category) {
        case StringCategory::CRYPTO: return "Crypto";
        case StringCategory::ANTI_VM: return "Anti-VM";
        case StringCategory::ANTI_DEBUG: return "Anti-Debug";
        case StringCategory::PERSISTENCE: return "Persistence";
        case StringCategory::MALWARE_API: return "Malware API";
        case StringCategory::DEBUGGING_TOOL: return "Debug Tool";
        case StringCategory::SANDBOX: return "Sandbox";
        case StringCategory::RECONNAISSANCE: return "Recon";
        case StringCategory::LATERAL_MOVEMENT: return "Lateral Move";
        case StringCategory::DATA_EXFILTRATION: return "Data Exfil";
        default: return "Benign";
    }
}

std::string StringAnalyzer::getCategoryColor(StringCategory category) {
    switch (category) {
        case StringCategory::CRYPTO: return "\033[93m";
        case StringCategory::ANTI_VM: return "\033[91m";
        case StringCategory::ANTI_DEBUG: return "\033[91m";
        case StringCategory::PERSISTENCE: return "\033[95m";
        case StringCategory::MALWARE_API: return "\033[91m";
        case StringCategory::DEBUGGING_TOOL: return "\033[94m";
        case StringCategory::SANDBOX: return "\033[93m";
        case StringCategory::RECONNAISSANCE: return "\033[96m";
        case StringCategory::LATERAL_MOVEMENT: return "\033[95m";
        case StringCategory::DATA_EXFILTRATION: return "\033[91m";
        default: return "\033[92m";
    }
}
