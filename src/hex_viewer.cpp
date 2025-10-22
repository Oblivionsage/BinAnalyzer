#include "hex_viewer.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>

HexViewer::HexViewer() : colorEnabled_(true) {
}

void HexViewer::displayBanner() {
    std::cout << COLOR_CYAN << COLOR_BOLD;
    std::cout << R"(
    ____  _          ___                __                     
   / __ )(_)___     /   |  ____  ____ _/ /_  ______  ___  _____
  / __  / / __ \   / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 / /_/ / / / / /  / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/_____/_/_/ /_/  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                       /____/                   
)" << COLOR_RESET;
    std::cout << COLOR_GREEN << "              Modern Binary Analysis Tool - Red Team Edition" << COLOR_RESET << "\n";
    std::cout << COLOR_YELLOW << "                              Version 1.0" << COLOR_RESET << "\n";
    std::cout << COLOR_GRAY << "                    github.com/Oblivionsage/BinAnalyzer\n" << COLOR_RESET;
    std::cout << "\n";
}

void HexViewer::setColorEnabled(bool enabled) {
    colorEnabled_ = enabled;
}

void HexViewer::displayHeader(const std::string& filename, size_t fileSize, const std::string& fileType) {
    std::cout << COLOR_BOLD << COLOR_CYAN;
    std::cout << "\n╔════════════════════════════════════ BinAnalyzer v1.0 ════════════════════════════════════╗\n";
    std::cout << COLOR_RESET;
    
    // Truncate filename if too long
    std::string displayName = filename;
    if (displayName.length() > 60) {
        displayName = "..." + displayName.substr(displayName.length() - 57);
    }
    
    std::cout << "║ " << COLOR_BOLD << "File: " << COLOR_RESET << displayName;
    
    // Safe padding calculation
    size_t nameLen = 7 + displayName.length(); // "File: " + name
    if (nameLen < 89) {
        size_t padding = 89 - nameLen;
        for (size_t i = 0; i < padding; i++) std::cout << " ";
    }
    std::cout << "║\n";
    
    // File size and type (simplified to avoid overflow)
    std::cout << "║ " << COLOR_BOLD << "Size: " << COLOR_RESET << fileSize << " bytes (" << (fileSize / 1024) << " KB)";
    std::cout << "  " << COLOR_BOLD << "Type: " << COLOR_RESET << fileType;
    
    // Calculate remaining space
    std::stringstream ss;
    ss << fileSize << " bytes (" << (fileSize / 1024) << " KB)  Type: " << fileType;
    std::string infoStr = ss.str();
    size_t totalLen = 8 + infoStr.length();
    
    if (totalLen < 89) {
        size_t padding = 89 - totalLen;
        for (size_t i = 0; i < padding; i++) std::cout << " ";
    }
    std::cout << "║\n";
}

void HexViewer::displayFileInfo(const std::string& md5, const std::string& sha256) {
    std::cout << "║ " << COLOR_BOLD << "MD5:    " << COLOR_RESET << COLOR_YELLOW << md5 << COLOR_RESET;
    
    // MD5 is always 32 chars, calculate safe padding
    size_t totalLen = 10 + 32; // "MD5:    " + hash
    if (totalLen < 89) {
        size_t padding = 89 - totalLen;
        for (size_t i = 0; i < padding; i++) std::cout << " ";
    }
    std::cout << "║\n";
    
    std::cout << "║ " << COLOR_BOLD << "SHA256: " << COLOR_RESET << COLOR_YELLOW << sha256 << COLOR_RESET;
    
    // SHA256 is always 64 chars, calculate safe padding
    totalLen = 10 + 64; // "SHA256: " + hash
    if (totalLen < 89) {
        size_t padding = 89 - totalLen;
        for (size_t i = 0; i < padding; i++) std::cout << " ";
    }
    std::cout << "║\n";
    
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════╣\n";
}

void HexViewer::displayStatistics(const std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    size_t nullBytes = 0;
    size_t printableBytes = 0;
    size_t controlBytes = 0;
    size_t extendedBytes = 0;
    
    // Count byte types
    for (uint8_t byte : data) {
        if (byte == 0x00) {
            nullBytes++;
        } else if (byte >= 0x20 && byte <= 0x7E) {
            printableBytes++;
        } else if (byte >= 0x01 && byte <= 0x1F) {
            controlBytes++;
        } else {
            extendedBytes++;
        }
    }
    
    // Calculate percentages
    double nullPercent = (nullBytes * 100.0) / data.size();
    double printablePercent = (printableBytes * 100.0) / data.size();
    double controlPercent = (controlBytes * 100.0) / data.size();
    double extendedPercent = (extendedBytes * 100.0) / data.size();
    
    // Simple entropy calculation
    int byteCounts[256] = {0};
    for (uint8_t byte : data) {
        byteCounts[byte]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / data.size();
            entropy -= p * log2(p);
        }
    }
    
    std::cout << "║ " << COLOR_BOLD << "Statistics:" << COLOR_RESET << "                                                                         ║\n";
    std::cout << "║  NULL bytes:       " << std::fixed << std::setprecision(2) << std::setw(6) << nullPercent << "%";
    std::cout << "     Printable ASCII: " << std::setw(6) << printablePercent << "%                         ║\n";
    std::cout << "║  Control chars:    " << std::setw(6) << controlPercent << "%";
    std::cout << "     Extended ASCII:  " << std::setw(6) << extendedPercent << "%                         ║\n";
    std::cout << "║  Entropy:          " << COLOR_YELLOW << std::setw(6) << entropy << COLOR_RESET << " / 8.00";
    
    // Entropy assessment
    if (entropy > 7.5) {
        std::cout << "  (" << COLOR_RED << "High - Likely packed/encrypted" << COLOR_RESET << ")";
    } else if (entropy > 6.5) {
        std::cout << "  (" << COLOR_YELLOW << "Medium - Possibly compressed" << COLOR_RESET << ")";
    } else {
        std::cout << "  (" << COLOR_GREEN << "Low - Normal executable" << COLOR_RESET << ")     ";
    }
    std::cout << "       ║\n";
    
    std::cout << "╠═══════════════════════════════════════════════════════════════════════════════════════╣\n";
}

void HexViewer::displayHex(const std::vector<uint8_t>& data, size_t offset, size_t maxBytes) {
    std::cout << "║                                                                                       ║\n";
    std::cout << "║  " << COLOR_BOLD << "Offset(h)" << COLOR_RESET << " │ ";
    std::cout << COLOR_BOLD << "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" << COLOR_RESET << " │ ";
    std::cout << COLOR_BOLD << "Decoded ASCII" << COLOR_RESET << "          ║\n";
    
    std::cout << "║ ───────────┼─────────────────────────────────────────────────┼────────────────────── ║\n";

    size_t bytesToDisplay = std::min(maxBytes, data.size() - offset);
    
    for (size_t i = 0; i < bytesToDisplay; i += 16) {
        // Offset
        std::cout << "║  " << COLOR_WHITE << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << (offset + i) << COLOR_RESET << "  │ ";
        
        // Hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < bytesToDisplay) {
                uint8_t byte = data[offset + i + j];
                std::cout << getColorForByte(byte);
                std::cout << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(byte);
                std::cout << COLOR_RESET << " ";
            } else {
                std::cout << "   ";
            }
        }
        
        std::cout << "│ ";
        
        // ASCII representation
        for (size_t j = 0; j < 16; j++) {
            if (i + j < bytesToDisplay) {
                uint8_t byte = data[offset + i + j];
                std::cout << getAsciiChar(byte);
            }
        }
        
        // Padding for ASCII section
        for (size_t j = bytesToDisplay - i; j < 16 && i + j >= bytesToDisplay; j++) {
            std::cout << " ";
        }
        
        std::cout << "               ║\n";
    }
    
    std::cout << "║                                                                                       ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << std::dec;  // Reset to decimal
}

std::string HexViewer::getColorForByte(uint8_t byte) const {
    if (!colorEnabled_) return "";
    
    // PE/ELF Magic bytes
    if (byte == 0x4D || byte == 0x5A || byte == 0x7F || byte == 0x45 || byte == 0x4C || byte == 0x46) {
        return COLOR_CYAN;
    }
    // NULL bytes
    else if (byte == 0x00) {
        return COLOR_GRAY;
    }
    // Printable ASCII
    else if (byte >= 0x20 && byte <= 0x7E) {
        return COLOR_GREEN;
    }
    // Control characters
    else if (byte >= 0x01 && byte <= 0x1F) {
        return COLOR_YELLOW;
    }
    // Extended ASCII
    else {
        return COLOR_BLUE;
    }
}

std::string HexViewer::getAsciiChar(uint8_t byte) const {
    if (byte >= 0x20 && byte <= 0x7E) {
        return std::string(1, static_cast<char>(byte));
    }
    return COLOR_GRAY + std::string(".") + COLOR_RESET;
}
