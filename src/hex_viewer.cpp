#include "hex_viewer.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

HexViewer::HexViewer() : colorEnabled_(true) {
}

void HexViewer::setColorEnabled(bool enabled) {
    colorEnabled_ = enabled;
}

void HexViewer::displayHeader(const std::string& filename, size_t fileSize, const std::string& fileType) {
    std::cout << COLOR_BOLD << COLOR_CYAN;
    std::cout << "\n╔════════════════════════════════════ BinAnalyzer v1.0 ════════════════════════════════════╗\n";
    std::cout << COLOR_RESET;
    
    std::cout << "║ " << COLOR_BOLD << "File: " << COLOR_RESET << filename;
    
    // Padding calculation
    size_t padding = 80 - filename.length() - 7;
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    
    std::cout << " ║\n";
    
    // File size and type
    std::cout << "║ " << COLOR_BOLD << "Size: " << COLOR_RESET << fileSize << " bytes";
    std::cout << " (" << (fileSize / 1024) << " KB)";
    
    std::cout << "        " << COLOR_BOLD << "Type: " << COLOR_RESET << fileType;
    
    // More padding
    std::stringstream sizeStr;
    sizeStr << fileSize << " bytes (" << (fileSize / 1024) << " KB)        Type: " << fileType;
    padding = 80 - sizeStr.str().length() - 13;
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    
    std::cout << " ║\n";
}

void HexViewer::displayFileInfo(const std::string& md5, const std::string& sha256) {
    std::cout << "║ " << COLOR_BOLD << "MD5:    " << COLOR_RESET << COLOR_YELLOW << md5;
    size_t padding = 80 - md5.length() - 10;
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    std::cout << COLOR_RESET << " ║\n";
    
    std::cout << "║ " << COLOR_BOLD << "SHA256: " << COLOR_RESET << COLOR_YELLOW << sha256;
    padding = 80 - sha256.length() - 10;
    for (size_t i = 0; i < padding; i++) std::cout << " ";
    std::cout << COLOR_RESET << " ║\n";
    
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
