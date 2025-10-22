#include "advanced_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <sstream>

// ============================================================================
// CONSTRUCTOR & INITIALIZATION
// ============================================================================

AdvancedAnalyzer::AdvancedAnalyzer() {
    initializePackerSignatures();
    initializeShellcodePatterns();
    initializeSuspiciousKeywords();
}

void AdvancedAnalyzer::initializePackerSignatures() {
    // UPX Packer
    PackerSignature upx;
    upx.name = "UPX";
    upx.sectionNames = {"UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1"};
    upx.minEntropy = 7.0;
    upx.hasAnomalousEP = true;
    upx.hasLowImportCount = true;
    packerSignatures_.push_back(upx);
    
    // Themida
    PackerSignature themida;
    themida.name = "Themida";
    themida.sectionNames = {".themida", ".winlice"};
    themida.minEntropy = 7.5;
    themida.hasAnomalousEP = true;
    themida.hasLowImportCount = true;
    packerSignatures_.push_back(themida);
    
    // VMProtect
    PackerSignature vmp;
    vmp.name = "VMProtect";
    vmp.sectionNames = {".vmp0", ".vmp1", ".vmp2"};
    vmp.minEntropy = 7.8;
    vmp.hasAnomalousEP = true;
    vmp.hasLowImportCount = true;
    packerSignatures_.push_back(vmp);
    
    // ASPack
    PackerSignature aspack;
    aspack.name = "ASPack";
    aspack.sectionNames = {".aspack", ".adata", "ASPack"};
    aspack.minEntropy = 7.2;
    aspack.hasAnomalousEP = true;
    aspack.hasLowImportCount = true;
    packerSignatures_.push_back(aspack);
    
    // PECompact
    PackerSignature pecompact;
    pecompact.name = "PECompact";
    pecompact.sectionNames = {".pec1", ".pec2", "PECompact2"};
    pecompact.minEntropy = 7.0;
    pecompact.hasAnomalousEP = true;
    pecompact.hasLowImportCount = true;
    packerSignatures_.push_back(pecompact);
    
    // MPRESS
    PackerSignature mpress;
    mpress.name = "MPRESS";
    mpress.sectionNames = {".MPRESS1", ".MPRESS2"};
    mpress.minEntropy = 7.3;
    mpress.hasAnomalousEP = true;
    mpress.hasLowImportCount = true;
    packerSignatures_.push_back(mpress);
}

void AdvancedAnalyzer::initializeShellcodePatterns() {
    // GetPC via CALL $+5 pattern
    ShellcodePattern getpc_call;
    getpc_call.type = ShellcodeType::GETPC_CALL;
    getpc_call.signature = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58}; // CALL $+5, POP EAX
    getpc_call.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    getpc_call.description = "GetPC technique (CALL/POP)";
    shellcodePatterns_.push_back(getpc_call);
    
    // FNSTENV GetPC
    ShellcodePattern fnstenv;
    fnstenv.type = ShellcodeType::GETPC_FNSTENV;
    fnstenv.signature = {0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4}; // FNSTENV [ESP-0xC]
    fnstenv.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    fnstenv.description = "GetPC technique (FNSTENV)";
    shellcodePatterns_.push_back(fnstenv);
    
    // Egg Hunter pattern (32-bit)
    ShellcodePattern egg_hunter;
    egg_hunter.type = ShellcodeType::EGG_HUNTER;
    egg_hunter.signature = {0x66, 0x81, 0xCA, 0xFF, 0x0F}; // OR DX, 0x0FFF
    egg_hunter.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    egg_hunter.description = "Egg hunter pattern";
    shellcodePatterns_.push_back(egg_hunter);
    
    // Metasploit common encoder stub
    ShellcodePattern metasploit;
    metasploit.type = ShellcodeType::METASPLOIT_PATTERN;
    metasploit.signature = {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00}; // CLD, CALL
    metasploit.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    metasploit.description = "Metasploit encoder stub";
    shellcodePatterns_.push_back(metasploit);
    
    // WinExec pattern
    ShellcodePattern winexec;
    winexec.type = ShellcodeType::REVERSE_SHELL;
    winexec.signature = {0x68, 0x63, 0x61, 0x6C, 0x63}; // PUSH "calc"
    winexec.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    winexec.description = "WinExec shellcode pattern";
    shellcodePatterns_.push_back(winexec);
}

void AdvancedAnalyzer::initializeSuspiciousKeywords() {
    // Cryptography keywords
    suspiciousKeywords_["AES"] = {StringCategory::CRYPTO, 0.6};
    suspiciousKeywords_["RC4"] = {StringCategory::CRYPTO, 0.7};
    suspiciousKeywords_["XOR"] = {StringCategory::CRYPTO, 0.5};
    suspiciousKeywords_["Base64"] = {StringCategory::CRYPTO, 0.4};
    suspiciousKeywords_["encrypt"] = {StringCategory::CRYPTO, 0.6};
    suspiciousKeywords_["decrypt"] = {StringCategory::CRYPTO, 0.6};
    suspiciousKeywords_["CryptEncrypt"] = {StringCategory::CRYPTO, 0.7};
    suspiciousKeywords_["CryptDecrypt"] = {StringCategory::CRYPTO, 0.7};
    
    // Anti-VM keywords
    suspiciousKeywords_["VMware"] = {StringCategory::ANTI_VM, 0.8};
    suspiciousKeywords_["VirtualBox"] = {StringCategory::ANTI_VM, 0.8};
    suspiciousKeywords_["VBOX"] = {StringCategory::ANTI_VM, 0.8};
    suspiciousKeywords_["QEMU"] = {StringCategory::ANTI_VM, 0.8};
    suspiciousKeywords_["Hyper-V"] = {StringCategory::ANTI_VM, 0.7};
    suspiciousKeywords_["VMM"] = {StringCategory::ANTI_VM, 0.6};
    
    // Anti-Debug keywords
    suspiciousKeywords_["IsDebuggerPresent"] = {StringCategory::ANTI_DEBUG, 0.9};
    suspiciousKeywords_["CheckRemoteDebuggerPresent"] = {StringCategory::ANTI_DEBUG, 0.9};
    suspiciousKeywords_["OutputDebugString"] = {StringCategory::ANTI_DEBUG, 0.7};
    suspiciousKeywords_["NtQueryInformationProcess"] = {StringCategory::ANTI_DEBUG, 0.8};
    suspiciousKeywords_["BeingDebugged"] = {StringCategory::ANTI_DEBUG, 0.8};
    
    // Persistence mechanisms
    suspiciousKeywords_["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"] = {StringCategory::PERSISTENCE, 0.8};
    suspiciousKeywords_["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"] = {StringCategory::PERSISTENCE, 0.9};
    suspiciousKeywords_["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"] = {StringCategory::PERSISTENCE, 0.9};
    suspiciousKeywords_["Startup"] = {StringCategory::PERSISTENCE, 0.6};
    suspiciousKeywords_["schtasks"] = {StringCategory::PERSISTENCE, 0.7};
    suspiciousKeywords_["at.exe"] = {StringCategory::PERSISTENCE, 0.7};
    
    // Debugging tools
    suspiciousKeywords_["OllyDbg"] = {StringCategory::DEBUGGING_TOOL, 0.7};
    suspiciousKeywords_["IDA"] = {StringCategory::DEBUGGING_TOOL, 0.6};
    suspiciousKeywords_["x64dbg"] = {StringCategory::DEBUGGING_TOOL, 0.7};
    suspiciousKeywords_["WinDbg"] = {StringCategory::DEBUGGING_TOOL, 0.6};
    suspiciousKeywords_["Immunity"] = {StringCategory::DEBUGGING_TOOL, 0.6};
    
    // Sandbox detection
    suspiciousKeywords_["Sandbox"] = {StringCategory::SANDBOX, 0.8};
    suspiciousKeywords_["Cuckoo"] = {StringCategory::SANDBOX, 0.8};
    suspiciousKeywords_["joe.exe"] = {StringCategory::SANDBOX, 0.9};
    suspiciousKeywords_["sample"] = {StringCategory::SANDBOX, 0.4};
    suspiciousKeywords_["malware"] = {StringCategory::SANDBOX, 0.5};
    
    // Reconnaissance
    suspiciousKeywords_["ipconfig"] = {StringCategory::RECONNAISSANCE, 0.6};
    suspiciousKeywords_["whoami"] = {StringCategory::RECONNAISSANCE, 0.6};
    suspiciousKeywords_["systeminfo"] = {StringCategory::RECONNAISSANCE, 0.7};
    suspiciousKeywords_["tasklist"] = {StringCategory::RECONNAISSANCE, 0.6};
    suspiciousKeywords_["netstat"] = {StringCategory::RECONNAISSANCE, 0.6};
    suspiciousKeywords_["GetComputerName"] = {StringCategory::RECONNAISSANCE, 0.5};
    suspiciousKeywords_["GetUserName"] = {StringCategory::RECONNAISSANCE, 0.5};
    
    // Lateral movement
    suspiciousKeywords_["psexec"] = {StringCategory::LATERAL_MOVEMENT, 0.9};
    suspiciousKeywords_["net use"] = {StringCategory::LATERAL_MOVEMENT, 0.7};
    suspiciousKeywords_["\\\\admin$"] = {StringCategory::LATERAL_MOVEMENT, 0.8};
    suspiciousKeywords_["\\\\C$"] = {StringCategory::LATERAL_MOVEMENT, 0.7};
    suspiciousKeywords_["WMI"] = {StringCategory::LATERAL_MOVEMENT, 0.6};
    
    // Data exfiltration
    suspiciousKeywords_["ftp"] = {StringCategory::DATA_EXFILTRATION, 0.5};
    suspiciousKeywords_["upload"] = {StringCategory::DATA_EXFILTRATION, 0.4};
    suspiciousKeywords_["POST"] = {StringCategory::DATA_EXFILTRATION, 0.3};
    suspiciousKeywords_["pastebin"] = {StringCategory::DATA_EXFILTRATION, 0.7};
    
    // Malware-specific APIs
    suspiciousKeywords_["CreateRemoteThread"] = {StringCategory::MALWARE_API, 0.9};
    suspiciousKeywords_["VirtualAllocEx"] = {StringCategory::MALWARE_API, 0.8};
    suspiciousKeywords_["WriteProcessMemory"] = {StringCategory::MALWARE_API, 0.9};
    suspiciousKeywords_["SetWindowsHookEx"] = {StringCategory::MALWARE_API, 0.7};
    suspiciousKeywords_["URLDownloadToFile"] = {StringCategory::MALWARE_API, 0.8};
}

// ============================================================================
// PACKER DETECTION
// ============================================================================

PackerDetectionResult AdvancedAnalyzer::detectPacker(const std::vector<uint8_t>& data) {
    PackerDetectionResult result;
    result.type = PackerType::NONE;
    result.name = "None";
    result.confidence = 0.0;
    result.isPacked = false;
    result.suspiciousEntropy = 0.0;
    result.entryPointAnomaly = false;
    result.importCount = 0;
    
    if (data.size() < 0x400) return result;
    
    // Check if PE
    if (data[0] != 0x4D || data[1] != 0x5A) return result;
    
    std::cout << "\033[93m[*] Analyzing packer signatures...\033[0m\n";
    
    // Extract section names
    std::vector<std::string> sectionNames;
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    if (peOffset + 0x100 < data.size()) {
        uint16_t numberOfSections = *reinterpret_cast<const uint16_t*>(&data[peOffset + 6]);
        uint16_t sizeOfOptionalHeader = *reinterpret_cast<const uint16_t*>(&data[peOffset + 20]);
        size_t sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
        
        for (int i = 0; i < numberOfSections && sectionTableOffset + 40 <= data.size(); i++) {
            char name[9] = {0};
            memcpy(name, &data[sectionTableOffset], 8);
            sectionNames.push_back(std::string(name));
            sectionTableOffset += 40;
        }
    }
    
    // Check for known packer signatures
    PackerType detectedType = identifyPackerBySection(sectionNames);
    
    if (detectedType != PackerType::NONE) {
        result.type = detectedType;
        result.name = getPackerName(detectedType);
        result.confidence = 0.9;
        result.isPacked = true;
        result.indicators.push_back("Known packer section names detected");
    }
    
    // Calculate entropy
    result.suspiciousEntropy = calculateMaxSectionEntropy(data);
    if (result.suspiciousEntropy > 7.0) {
        result.indicators.push_back("High entropy (" + std::to_string(result.suspiciousEntropy).substr(0, 4) + ") indicates compression/encryption");
        if (result.confidence < 0.6) result.confidence = 0.6;
        if (result.type == PackerType::NONE) {
            result.type = PackerType::GENERIC_PACKER;
            result.name = "Generic Packer (High Entropy)";
            result.isPacked = true;
        }
    }
    
    // Check entry point anomaly
    result.entryPointAnomaly = checkEntryPointAnomaly(data);
    if (result.entryPointAnomaly) {
        result.indicators.push_back("Entry point in non-standard section");
        if (result.confidence < 0.5) result.confidence = 0.5;
    }
    
    // Count imports
    result.importCount = countImports(data);
    if (result.importCount < 10 && result.importCount > 0) {
        result.indicators.push_back("Unusually low import count (" + std::to_string(result.importCount) + ")");
        if (result.confidence < 0.4) result.confidence = 0.4;
    }
    
    // Final assessment
    if (result.indicators.size() >= 2 && result.type == PackerType::NONE) {
        result.type = PackerType::UNKNOWN_PACKER;
        result.name = "Unknown Packer";
        result.isPacked = true;
        result.confidence = 0.7;
    }
    
    return result;
}

PackerType AdvancedAnalyzer::identifyPackerBySection(const std::vector<std::string>& sectionNames) {
    for (const auto& sig : packerSignatures_) {
        for (const auto& sigName : sig.sectionNames) {
            for (const auto& secName : sectionNames) {
                if (secName.find(sigName) != std::string::npos) {
                    if (sig.name == "UPX") return PackerType::UPX;
                    if (sig.name == "Themida") return PackerType::THEMIDA;
                    if (sig.name == "VMProtect") return PackerType::VMPROTECT;
                    if (sig.name == "ASPack") return PackerType::ASPACK;
                    if (sig.name == "PECompact") return PackerType::PECOMPACT;
                    if (sig.name == "MPRESS") return PackerType::MPRESS;
                }
            }
        }
    }
    return PackerType::NONE;
}

bool AdvancedAnalyzer::checkEntryPointAnomaly(const std::vector<uint8_t>& data) {
    return false; // Placeholder
}

double AdvancedAnalyzer::calculateMaxSectionEntropy(const std::vector<uint8_t>& data) {
    size_t sampleSize = std::min(data.size(), static_cast<size_t>(65536));
    
    int byteCounts[256] = {0};
    for (size_t i = 0; i < sampleSize; i++) {
        byteCounts[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / sampleSize;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

int AdvancedAnalyzer::countImports(const std::vector<uint8_t>& data) {
    return 50; // Placeholder
}

// ============================================================================
// SHELLCODE DETECTION
// ============================================================================

ShellcodeAnalysisResult AdvancedAnalyzer::detectShellcode(const std::vector<uint8_t>& data) {
    ShellcodeAnalysisResult result;
    result.shellcodeFound = false;
    result.totalPatterns = 0;
    
    if (data.size() < 100) return result;
    
    std::cout << "\033[93m[*] Scanning for shellcode patterns...\033[0m\n";
    
    size_t scanSize = std::min(data.size(), static_cast<size_t>(2 * 1024 * 1024));
    
    // Check for NOP sleds
    for (size_t i = 0; i < scanSize - 20; i++) {
        if (detectNOPSled(data, i)) {
            ShellcodeDetection detection;
            detection.type = ShellcodeType::NOP_SLED;
            detection.offset = i;
            detection.description = "NOP sled detected (potential shellcode buffer)";
            detection.confidence = 0.7;
            
            size_t nopLen = 0;
            while (i + nopLen < scanSize && data[i + nopLen] == 0x90) {
                nopLen++;
            }
            detection.length = nopLen;
            
            result.detections.push_back(detection);
            result.shellcodeFound = true;
            
            i += nopLen;
            
            if (result.detections.size() >= 20) break;
        }
    }
    
    // Check for known shellcode patterns
    for (size_t i = 0; i < scanSize - 20; i++) {
        for (const auto& pattern : shellcodePatterns_) {
            if (matchPattern(data, i, pattern.signature, pattern.mask)) {
                ShellcodeDetection detection;
                detection.type = pattern.type;
                detection.offset = i;
                detection.length = pattern.signature.size();
                detection.description = pattern.description;
                detection.confidence = 0.8;
                
                result.detections.push_back(detection);
                result.shellcodeFound = true;
                
                if (result.detections.size() >= 20) break;
            }
        }
        if (result.detections.size() >= 20) break;
        
        if (i % 100000 == 0 && i > 0) {
            std::cout << "\r\033[93m[*] Scanned " << (i / 1024) << " KB...\033[0m" << std::flush;
        }
    }
    
    if (!result.detections.empty()) {
        std::cout << "\r\033[92m[+] Found " << result.detections.size() << " shellcode patterns\033[0m\n";
    }
    
    result.totalPatterns = result.detections.size();
    return result;
}

bool AdvancedAnalyzer::matchPattern(const std::vector<uint8_t>& data, size_t offset,
                                     const std::vector<uint8_t>& pattern,
                                     const std::vector<uint8_t>& mask) {
    if (offset + pattern.size() > data.size()) return false;
    
    for (size_t i = 0; i < pattern.size(); i++) {
        if ((data[offset + i] & mask[i]) != (pattern[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

bool AdvancedAnalyzer::detectNOPSled(const std::vector<uint8_t>& data, size_t offset) {
    const size_t MIN_NOP_COUNT = 20;
    
    if (offset + MIN_NOP_COUNT > data.size()) return false;
    
    for (size_t i = 0; i < MIN_NOP_COUNT; i++) {
        if (data[offset + i] != 0x90) {
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// NETWORK IOC EXTRACTION - NO REGEX
// ============================================================================

IOCExtractionResult AdvancedAnalyzer::extractIOCs(const std::vector<uint8_t>& data) {
    IOCExtractionResult result;
    result.networkActivitySuspected = false;
    
    std::cout << "\033[93m[*] Extracting network IOCs...\033[0m\n";
    
    std::string currentString;
    size_t stringStart = 0;
    
    for (size_t i = 0; i < std::min(data.size(), static_cast<size_t>(2 * 1024 * 1024)); i++) {
        uint8_t byte = data[i];
        
        if ((byte >= 0x20 && byte <= 0x7E) || byte == 0x09) {
            if (currentString.empty()) {
                stringStart = i;
            }
            currentString += static_cast<char>(byte);
        } else {
            if (currentString.length() >= 7) {
                if (isValidIPv4(currentString)) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::IPV4;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::IPV4]++;
                    result.networkActivitySuspected = true;
                }
                else if (isValidDomain(currentString)) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::DOMAIN;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::DOMAIN]++;
                    result.networkActivitySuspected = true;
                }
                else if (currentString.find("http://") != std::string::npos || 
                         currentString.find("https://") != std::string::npos ||
                         currentString.find("ftp://") != std::string::npos) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::URL;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::URL]++;
                    result.networkActivitySuspected = true;
                }
                else if (isValidEmail(currentString)) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::EMAIL;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::EMAIL]++;
                }
            }
            currentString.clear();
        }
        
        if (result.iocs.size() >= 50) break;
    }
    
    return result;
}

bool AdvancedAnalyzer::isValidIPv4(const std::string& str) {
    if (str.length() < 7 || str.length() > 15) return false;
    
    int dots = 0;
    int currentNum = 0;
    bool hasDigit = false;
    
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '.') {
            if (!hasDigit) return false;
            if (currentNum > 255) return false;
            dots++;
            currentNum = 0;
            hasDigit = false;
        } else if (str[i] >= '0' && str[i] <= '9') {
            currentNum = currentNum * 10 + (str[i] - '0');
            hasDigit = true;
            if (currentNum > 255) return false;
        } else {
            return false;
        }
    }
    
    if (!hasDigit || currentNum > 255) return false;
    
    return (dots == 3);
}

bool AdvancedAnalyzer::isValidDomain(const std::string& str) {
    if (str.find('.') == std::string::npos) return false;
    if (str.length() < 4) return false;
    
    std::vector<std::string> tlds = {".com", ".net", ".org", ".io", ".co", ".ru", ".cn", 
                                      ".de", ".uk", ".edu", ".gov", ".mil", ".info", ".biz"};
    
    bool hasTLD = false;
    for (const auto& tld : tlds) {
        if (str.length() >= tld.length()) {
            std::string ending = str.substr(str.length() - tld.length());
            std::transform(ending.begin(), ending.end(), ending.begin(), ::tolower);
            if (ending == tld) {
                hasTLD = true;
                break;
            }
        }
    }
    
    if (!hasTLD) return false;
    
    for (char c : str) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return false;
        }
    }
    
    if (str[0] == '.' || str[0] == '-' || 
        str[str.length()-1] == '.' || str[str.length()-1] == '-') {
        return false;
    }
    
    return true;
}

bool AdvancedAnalyzer::isValidEmail(const std::string& str) {
    size_t atPos = str.find('@');
    if (atPos == std::string::npos || atPos == 0 || atPos == str.length() - 1) {
        return false;
    }
    
    if (str.find('@', atPos + 1) != std::string::npos) {
        return false;
    }
    
    std::string domain = str.substr(atPos + 1);
    if (!isValidDomain(domain)) {
        return false;
    }
    
    std::string local = str.substr(0, atPos);
    if (local.empty()) return false;
    
    for (char c : local) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '.' || c == '_' || 
              c == '-' || c == '+' || c == '%')) {
            return false;
        }
    }
    
    return true;
}

std::string AdvancedAnalyzer::extractContext(const std::vector<uint8_t>& data, 
                                               size_t offset, size_t length) {
    const size_t contextSize = 20;
    size_t start = (offset > contextSize) ? offset - contextSize : 0;
    size_t end = std::min(offset + length + contextSize, data.size());
    
    std::string context;
    for (size_t i = start; i < end; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            context += static_cast<char>(data[i]);
        } else {
            context += '.';
        }
    }
    
    return context;
}

// ============================================================================
// SUSPICIOUS STRINGS ANALYSIS
// ============================================================================

StringAnalysisResult AdvancedAnalyzer::analyzeSuspiciousStrings(const std::vector<uint8_t>& data) {
    StringAnalysisResult result;
    result.overallSuspicionScore = 0.0;
    result.highlyMalicious = false;
    
    std::cout << "\033[93m[*] Analyzing suspicious strings...\033[0m\n";
    
    std::string currentString;
    size_t stringStart = 0;
    
    for (size_t i = 0; i < std::min(data.size(), static_cast<size_t>(2 * 1024 * 1024)); i++) {
        uint8_t byte = data[i];
        
        if (byte >= 0x20 && byte <= 0x7E) {
            if (currentString.empty()) {
                stringStart = i;
            }
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
        for (const auto& str : result.suspiciousStrings) {
            totalScore += str.suspicionScore;
        }
        result.overallSuspicionScore = totalScore / result.suspiciousStrings.size();
        result.highlyMalicious = (result.overallSuspicionScore > 0.7);
    }
    
    return result;
}

StringCategory AdvancedAnalyzer::categorizeString(const std::string& str, double& score) {
    score = 0.0;
    StringCategory bestCategory = StringCategory::BENIGN;
    
    for (const auto& keyword : suspiciousKeywords_) {
        if (str.find(keyword.first) != std::string::npos) {
            if (keyword.second.second > score) {
                score = keyword.second.second;
                bestCategory = keyword.second.first;
            }
        }
    }
    
    return bestCategory;
}

// (Part 3 - Display Functions)

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

void AdvancedAnalyzer::displayPackerResults(const PackerDetectionResult& result) {
    std::cout << "\n\033[1;96m╔═════════════════════ PACKER DETECTION ═════════════════════╗\033[0m\n";
    
    std::string statusColor = result.isPacked ? "\033[91m" : "\033[92m";
    std::string status = result.isPacked ? "PACKED" : "NOT PACKED";
    
    std::cout << "║ " << "\033[1mStatus:\033[0m " << statusColor << status << "\033[0m";
    
    size_t padding = 60 - status.length();
    if (padding > 0 && padding < 100) {
        for (size_t i = 0; i < padding; i++) std::cout << " ";
    }
    std::cout << "║\n";
    
    if (result.isPacked) {
        std::cout << "║ " << "\033[1mPacker:\033[0m " << result.name;
        padding = 60 - result.name.length();
        if (padding > 0 && padding < 100) {
            for (size_t i = 0; i < padding; i++) std::cout << " ";
        }
        std::cout << "║\n";
        
        std::cout << "║ " << "\033[1mConfidence:\033[0m " << std::fixed << std::setprecision(0) 
                  << (result.confidence * 100) << "%";
        padding = 54;
        for (size_t i = 0; i < padding; i++) std::cout << " ";
        std::cout << "║\n";
    }
    
    if (!result.indicators.empty()) {
        std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "║ \033[1mIndicators:\033[0m                                              ║\n";
        
        for (const auto& indicator : result.indicators) {
            std::cout << "║   • " << indicator.substr(0, 54);
            padding = 56 - std::min(indicator.length(), static_cast<size_t>(54));
            for (size_t i = 0; i < padding; i++) std::cout << " ";
            std::cout << "║\n";
        }
    }
    
    std::cout << "\033[1;96m╚═════════════════════════════════════════════════════════════╝\033[0m\n";
}

void AdvancedAnalyzer::displayShellcodeResults(const ShellcodeAnalysisResult& result) {
    if (result.detections.empty()) {
        std::cout << "\n\033[92m[+] No shellcode patterns detected\033[0m\n";
        return;
    }
    
    std::cout << "\n\033[1;96m╔═══════════════════ SHELLCODE DETECTION ═══════════════════╗\033[0m\n";
    std::cout << "║ " << "\033[1mPatterns Found:\033[0m " << result.totalPatterns << " suspicious sequences";
    
    size_t padding = 36 - std::to_string(result.totalPatterns).length();
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    std::cout << "║\n";
    
    std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════╣\033[0m\n";
    
    size_t displayCount = std::min(result.detections.size(), static_cast<size_t>(10));
    for (size_t i = 0; i < displayCount; i++) {
        const auto& detection = result.detections[i];
        
        std::cout << "║ \033[91m[!]\033[0m 0x" << std::hex << std::setfill('0') << std::setw(8) << detection.offset << std::dec;
        std::cout << "  " << detection.description.substr(0, 35);
        padding = 38 - std::min(detection.description.length(), static_cast<size_t>(35));
        for (size_t j = 0; j < padding; j++) std::cout << " ";
        std::cout << "║\n";
    }
    
    if (result.detections.size() > displayCount) {
        std::cout << "║ \033[90m... and " << (result.detections.size() - displayCount) << " more\033[0m";
        padding = 51 - std::to_string(result.detections.size() - displayCount).length();
        for (size_t i = 0; i < padding; i++) std::cout << " ";
        std::cout << "║\n";
    }
    
    std::cout << "\033[1;96m╚═════════════════════════════════════════════════════════════╝\033[0m\n";
}

void AdvancedAnalyzer::displayIOCResults(const IOCExtractionResult& result) {
    if (result.iocs.empty()) {
        std::cout << "\n\033[92m[+] No network IOCs detected\033[0m\n";
        return;
    }
    
    std::cout << "\n\033[1;96m╔═══════════════════ NETWORK IOCs FOUND ═══════════════════╗\033[0m\n";
    std::cout << "║ " << "\033[1mTotal IOCs:\033[0m " << result.iocs.size();
    
    size_t padding = 55 - std::to_string(result.iocs.size()).length();
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    std::cout << "║\n";
    
    if (!result.counts.empty()) {
        std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════╣\033[0m\n";
        for (const auto& count : result.counts) {
            std::cout << "║   " << getIOCTypeName(count.first) << ": " << count.second;
            padding = 57 - (getIOCTypeName(count.first).length() + std::to_string(count.second).length());
            for (size_t i = 0; i < padding; i++) std::cout << " ";
            std::cout << "║\n";
        }
    }
    
    std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════╣\033[0m\n";
    
    size_t displayCount = std::min(result.iocs.size(), static_cast<size_t>(15));
    for (size_t i = 0; i < displayCount; i++) {
        const auto& ioc = result.iocs[i];
        
        std::string typeColor = (ioc.type == IOCType::IPV4 || ioc.type == IOCType::URL) ? "\033[91m" : "\033[93m";
        std::cout << "║ " << typeColor << ioc.value.substr(0, 58) << "\033[0m";
        padding = 60 - std::min(ioc.value.length(), static_cast<size_t>(58));
        for (size_t j = 0; j < padding; j++) std::cout << " ";
        std::cout << "║\n";
    }
    
    if (result.iocs.size() > displayCount) {
        std::cout << "║ \033[90m... and " << (result.iocs.size() - displayCount) << " more\033[0m";
        padding = 51 - std::to_string(result.iocs.size() - displayCount).length();
        for (size_t i = 0; i < padding; i++) std::cout << " ";
        std::cout << "║\n";
    }
    
    std::cout << "\033[1;96m╚═════════════════════════════════════════════════════════════╝\033[0m\n";
}

void AdvancedAnalyzer::displayStringResults(const StringAnalysisResult& result) {
    if (result.suspiciousStrings.empty()) {
        std::cout << "\n\033[92m[+] No highly suspicious strings detected\033[0m\n";
        return;
    }
    
    std::cout << "\n\033[1;96m╔═════════════════ SUSPICIOUS STRINGS ═════════════════════╗\033[0m\n";
    std::cout << "║ " << "\033[1mTotal Found:\033[0m " << result.suspiciousStrings.size();
    
    size_t padding = 54 - std::to_string(result.suspiciousStrings.size()).length();
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    std::cout << "║\n";
    
    std::cout << "║ " << "\033[1mSuspicion Score:\033[0m " << std::fixed << std::setprecision(2) 
              << (result.overallSuspicionScore * 100) << "%";
    padding = 48;
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    std::cout << "║\n";
    
    if (!result.categoryCounts.empty()) {
        std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "║ \033[1mCategories:\033[0m                                              ║\n";
        
        for (const auto& cat : result.categoryCounts) {
            std::cout << "║   " << getCategoryColor(cat.first) << "●\033[0m ";
            std::cout << getCategoryName(cat.first) << ": " << cat.second;
            padding = 54 - (getCategoryName(cat.first).length() + std::to_string(cat.second).length());
            for (size_t i = 0; i < padding; i++) std::cout << " ";
            std::cout << "║\n";
        }
    }
    
    std::cout << "\033[1;96m╠═════════════════════════════════════════════════════════════╣\033[0m\n";
    
    size_t displayCount = std::min(result.suspiciousStrings.size(), static_cast<size_t>(10));
    for (size_t i = 0; i < displayCount; i++) {
        const auto& str = result.suspiciousStrings[i];
        
        std::cout << "║ " << getCategoryColor(str.category) << str.value.substr(0, 58) << "\033[0m";
        padding = 60 - std::min(str.value.length(), static_cast<size_t>(58));
        for (size_t j = 0; j < padding; j++) std::cout << " ";
        std::cout << "║\n";
    }
    
    if (result.suspiciousStrings.size() > displayCount) {
        std::cout << "║ \033[90m... and " << (result.suspiciousStrings.size() - displayCount) << " more\033[0m";
        padding = 51 - std::to_string(result.suspiciousStrings.size() - displayCount).length();
        for (size_t i = 0; i < padding; i++) std::cout << " ";
        std::cout << "║\n";
    }
    
    std::cout << "\033[1;96m╚═════════════════════════════════════════════════════════════╝\033[0m\n";
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string AdvancedAnalyzer::getPackerName(PackerType type) {
    switch (type) {
        case PackerType::UPX: return "UPX";
        case PackerType::THEMIDA: return "Themida";
        case PackerType::VMPROTECT: return "VMProtect";
        case PackerType::ASPACK: return "ASPack";
        case PackerType::ARMADILLO: return "Armadillo";
        case PackerType::PECOMPACT: return "PECompact";
        case PackerType::MPRESS: return "MPRESS";
        case PackerType::GENERIC_PACKER: return "Generic Packer";
        case PackerType::UNKNOWN_PACKER: return "Unknown Packer";
        default: return "None";
    }
}

std::string AdvancedAnalyzer::getShellcodeTypeName(ShellcodeType type) {
    switch (type) {
        case ShellcodeType::NOP_SLED: return "NOP Sled";
        case ShellcodeType::EGG_HUNTER: return "Egg Hunter";
        case ShellcodeType::GETPC_CALL: return "GetPC (CALL/POP)";
        case ShellcodeType::GETPC_FNSTENV: return "GetPC (FNSTENV)";
        case ShellcodeType::METASPLOIT_PATTERN: return "Metasploit Pattern";
        case ShellcodeType::REVERSE_SHELL: return "Reverse Shell";
        default: return "Unknown";
    }
}

std::string AdvancedAnalyzer::getIOCTypeName(IOCType type) {
    switch (type) {
        case IOCType::IPV4: return "IPv4 Address";
        case IOCType::IPV6: return "IPv6 Address";
        case IOCType::URL: return "URL";
        case IOCType::DOMAIN: return "Domain";
        case IOCType::EMAIL: return "Email";
        case IOCType::BITCOIN_ADDRESS: return "Bitcoin Address";
        default: return "Unknown";
    }
}

std::string AdvancedAnalyzer::getCategoryName(StringCategory category) {
    switch (category) {
        case StringCategory::CRYPTO: return "Cryptography";
        case StringCategory::ANTI_VM: return "Anti-VM";
        case StringCategory::ANTI_DEBUG: return "Anti-Debug";
        case StringCategory::PERSISTENCE: return "Persistence";
        case StringCategory::MALWARE_API: return "Malware API";
        case StringCategory::DEBUGGING_TOOL: return "Debugging Tool";
        case StringCategory::SANDBOX: return "Sandbox Detection";
        case StringCategory::RECONNAISSANCE: return "Reconnaissance";
        case StringCategory::LATERAL_MOVEMENT: return "Lateral Movement";
        case StringCategory::DATA_EXFILTRATION: return "Data Exfiltration";
        default: return "Benign";
    }
}

std::string AdvancedAnalyzer::getCategoryColor(StringCategory category) {
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
