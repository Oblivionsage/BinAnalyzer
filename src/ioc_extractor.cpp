#include "ioc_extractor.hpp"
#include <iostream>
#include <algorithm>

IOCExtractor::IOCExtractor() {
}

IOCExtractionResult IOCExtractor::extract(const std::vector<uint8_t>& data) {
    IOCExtractionResult result;
    result.networkActivitySuspected = false;
    
    std::cout << "\033[93m[*] Extracting network IOCs...\033[0m\n";
    
    std::string currentString;
    size_t stringStart = 0;
    
    for (size_t i = 0; i < std::min(data.size(), static_cast<size_t>(2 * 1024 * 1024)); i++) {
        uint8_t byte = data[i];
        
        if ((byte >= 0x20 && byte <= 0x7E) || byte == 0x09) {
            if (currentString.empty()) stringStart = i;
            currentString += static_cast<char>(byte);
        } else {
            if (currentString.length() >= 7) {
                if (isValidIPv4(currentString)) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::IPV4_ADDRESS;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::IPV4_ADDRESS]++;
                    result.networkActivitySuspected = true;
                }
                else if (isValidDomain(currentString)) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::DOMAIN_NAME;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::DOMAIN_NAME]++;
                    result.networkActivitySuspected = true;
                }
                else if (currentString.find("http://") != std::string::npos || 
                         currentString.find("https://") != std::string::npos ||
                         currentString.find("ftp://") != std::string::npos) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::URL_ADDRESS;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::URL_ADDRESS]++;
                    result.networkActivitySuspected = true;
                }
                else if (isValidEmail(currentString)) {
                    NetworkIOC ioc;
                    ioc.type = IOCType::EMAIL_ADDRESS;
                    ioc.value = currentString;
                    ioc.offset = stringStart;
                    ioc.context = extractContext(data, stringStart, currentString.length());
                    result.iocs.push_back(ioc);
                    result.counts[IOCType::EMAIL_ADDRESS]++;
                }
            }
            currentString.clear();
        }
        
        if (result.iocs.size() >= 50) break;
    }
    
    return result;
}

bool IOCExtractor::isValidIPv4(const std::string& str) {
    if (str.length() < 7 || str.length() > 15) return false;
    
    int dots = 0, currentNum = 0;
    bool hasDigit = false;
    
    for (char c : str) {
        if (c == '.') {
            if (!hasDigit || currentNum > 255) return false;
            dots++;
            currentNum = 0;
            hasDigit = false;
        } else if (c >= '0' && c <= '9') {
            currentNum = currentNum * 10 + (c - '0');
            hasDigit = true;
            if (currentNum > 255) return false;
        } else {
            return false;
        }
    }
    
    return (dots == 3 && hasDigit && currentNum <= 255);
}

bool IOCExtractor::isValidDomain(const std::string& str) {
    if (str.find('.') == std::string::npos || str.length() < 4) return false;
    
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
              (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
    }
    
    return (str[0] != '.' && str[0] != '-' && 
            str[str.length()-1] != '.' && str[str.length()-1] != '-');
}

bool IOCExtractor::isValidEmail(const std::string& str) {
    size_t atPos = str.find('@');
    if (atPos == std::string::npos || atPos == 0 || atPos == str.length() - 1) return false;
    if (str.find('@', atPos + 1) != std::string::npos) return false;
    
    return isValidDomain(str.substr(atPos + 1));
}

std::string IOCExtractor::extractContext(const std::vector<uint8_t>& data, 
                                          size_t offset, size_t length) {
    const size_t contextSize = 20;
    size_t start = (offset > contextSize) ? offset - contextSize : 0;
    size_t end = std::min(offset + length + contextSize, data.size());
    
    std::string context;
    for (size_t i = start; i < end; i++) {
        context += (data[i] >= 0x20 && data[i] <= 0x7E) ? static_cast<char>(data[i]) : '.';
    }
    return context;
}

void IOCExtractor::displayResults(const IOCExtractionResult& result) {
    if (result.iocs.empty()) return;
    
    std::cout << "\n[*] Network Indicators\n";
    std::cout << "----------------------\n";
    std::cout << "Total: " << result.iocs.size() << "\n\n";
    
    for (const auto& count : result.counts) {
        std::cout << "  " << getIOCTypeName(count.first) << ": " << count.second << "\n";
    }
    std::cout << "\n";
    
    size_t displayCount = std::min(result.iocs.size(), static_cast<size_t>(10));
    for (size_t i = 0; i < displayCount; i++) {
        const auto& ioc = result.iocs[i];
        std::string typeColor = (ioc.type == IOCType::IPV4_ADDRESS || ioc.type == IOCType::URL_ADDRESS) 
                                ? "\033[91m" : "\033[93m";
        std::cout << "  " << typeColor << ioc.value << "\033[0m\n";
    }
    
    if (result.iocs.size() > displayCount) {
        std::cout << "  ... and " << (result.iocs.size() - displayCount) << " more\n";
    }
    std::cout << "\n";
    //TODO
    
    if (result.iocs.size() > displayCount) {
        std::cout << "  ... and " << (result.iocs.size() - displayCount) << " more\n";
    }
    std::cout << "\n";
}

std::string IOCExtractor::getIOCTypeName(IOCType type) {
    switch (type) {
        case IOCType::IPV4_ADDRESS: return "IPv4";
        case IOCType::IPV6_ADDRESS: return "IPv6";
        case IOCType::URL_ADDRESS: return "URL";
        case IOCType::DOMAIN_NAME: return "Domain";
        case IOCType::EMAIL_ADDRESS: return "Email";
        case IOCType::BITCOIN_ADDRESS: return "Bitcoin";
        default: return "Unknown";
    }
}
