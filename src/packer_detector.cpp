#include "packer_detector.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cmath>
#include <algorithm>

PackerDetector::PackerDetector() {
    initializeSignatures();
}

void PackerDetector::initializeSignatures() {
    PackerSignature upx;
    upx.name = "UPX";
    upx.sectionNames = {"UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1"};
    upx.minEntropy = 7.0;
    upx.hasAnomalousEP = true;
    upx.hasLowImportCount = true;
    signatures_.push_back(upx);
    
    PackerSignature themida;
    themida.name = "Themida";
    themida.sectionNames = {".themida", ".winlice"};
    themida.minEntropy = 7.5;
    themida.hasAnomalousEP = true;
    themida.hasLowImportCount = true;
    signatures_.push_back(themida);
    
    PackerSignature vmp;
    vmp.name = "VMProtect";
    vmp.sectionNames = {".vmp0", ".vmp1", ".vmp2"};
    vmp.minEntropy = 7.8;
    vmp.hasAnomalousEP = true;
    vmp.hasLowImportCount = true;
    signatures_.push_back(vmp);
    
    PackerSignature aspack;
    aspack.name = "ASPack";
    aspack.sectionNames = {".aspack", ".adata", "ASPack"};
    aspack.minEntropy = 7.2;
    aspack.hasAnomalousEP = true;
    aspack.hasLowImportCount = true;
    signatures_.push_back(aspack);
    
    PackerSignature pecompact;
    pecompact.name = "PECompact";
    pecompact.sectionNames = {".pec1", ".pec2", "PECompact2"};
    pecompact.minEntropy = 7.0;
    pecompact.hasAnomalousEP = true;
    pecompact.hasLowImportCount = true;
    signatures_.push_back(pecompact);
    
    PackerSignature mpress;
    mpress.name = "MPRESS";
    mpress.sectionNames = {".MPRESS1", ".MPRESS2"};
    mpress.minEntropy = 7.3;
    mpress.hasAnomalousEP = true;
    mpress.hasLowImportCount = true;
    signatures_.push_back(mpress);
}

PackerDetectionResult PackerDetector::detect(const std::vector<uint8_t>& data) {
    PackerDetectionResult result;
    result.type = PackerType::NONE;
    result.name = "None";
    result.confidence = 0.0;
    result.isPacked = false;
    result.suspiciousEntropy = 0.0;
    result.entryPointAnomaly = false;
    result.importCount = 0;
    
    if (data.size() < 0x400) return result;
    if (data[0] != 0x4D || data[1] != 0x5A) return result;
    
    std::cout << "\033[93m[*] Analyzing packer signatures...\033[0m\n";
    
    // Parse PE sections
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
    
    // Identify by section names
    PackerType detectedType = identifyBySection(sectionNames);
    if (detectedType != PackerType::NONE) {
        result.type = detectedType;
        result.name = getPackerName(detectedType);
        result.confidence = 0.9;
        result.isPacked = true;
        result.indicators.push_back("Known packer section names");
    }
    
    // Check entropy
    result.suspiciousEntropy = calculateEntropy(data);
    if (result.suspiciousEntropy > 7.0) {
        result.indicators.push_back("High entropy (compressed/encrypted)");
        if (result.confidence < 0.6) result.confidence = 0.6;
        if (result.type == PackerType::NONE) {
            result.type = PackerType::GENERIC_PACKER;
            result.name = "Generic Packer";
            result.isPacked = true;
        }
    }
    
    // Generic detection
    if (result.indicators.size() >= 2 && result.type == PackerType::NONE) {
        result.type = PackerType::UNKNOWN_PACKER;
        result.name = "Unknown Packer";
        result.isPacked = true;
        result.confidence = 0.7;
    }
    
    return result;
}

PackerType PackerDetector::identifyBySection(const std::vector<std::string>& sectionNames) {
    for (const auto& sig : signatures_) {
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

double PackerDetector::calculateEntropy(const std::vector<uint8_t>& data) {
    size_t sampleSize = std::min(data.size(), static_cast<size_t>(65536));
    int byteCounts[256] = {0};
    for (size_t i = 0; i < sampleSize; i++) byteCounts[data[i]]++;
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / sampleSize;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void PackerDetector::displayResults(const PackerDetectionResult& result) {
    std::cout << "\n[*] Packer Detection\n";
    std::cout << "--------------------\n";
    
    if (!result.isPacked) {
        std::cout << "Status: CLEAN\n";
        return;
    }
    
    std::cout << "Status: \033[91mPACKED\033[0m\n";
    std::cout << "Packer: " << result.name << "\n";
    std::cout << "Confidence: " << static_cast<int>(result.confidence * 100) << "%\n";
    
    if (!result.indicators.empty()) {
        std::cout << "\nIndicators:\n";
        for (size_t i = 0; i < std::min(result.indicators.size(), static_cast<size_t>(3)); i++) {
            std::cout << "  - " << result.indicators[i] << "\n";
        }
    }
    std::cout << "\n";
}

std::string PackerDetector::getPackerName(PackerType type) {
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
