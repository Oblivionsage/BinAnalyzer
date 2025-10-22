#ifndef HEX_VIEWER_HPP
#define HEX_VIEWER_HPP

#include <vector>
#include <cstdint>
#include <string>

class HexViewer {
public:
    HexViewer();
    
    static void displayBanner();
    void displayHex(const std::vector<uint8_t>& data, size_t offset = 0, size_t maxBytes = 256);
    void displayHeader(const std::string& filename, size_t fileSize, const std::string& fileType);
    void displayFileInfo(const std::string& md5, const std::string& sha256);
    void displayStatistics(const std::vector<uint8_t>& data);
    void setColorEnabled(bool enabled);

private:
    bool colorEnabled_;
    
    std::string getColorForByte(uint8_t byte) const;
    std::string getAsciiChar(uint8_t byte) const;
    void printSeparatorLine() const;
    void printBorder(const std::string& text) const;
    
    // ANSI color codes
    static constexpr const char* COLOR_RESET = "\033[0m";
    static constexpr const char* COLOR_CYAN = "\033[96m";
    static constexpr const char* COLOR_GREEN = "\033[92m";
    static constexpr const char* COLOR_YELLOW = "\033[93m";
    static constexpr const char* COLOR_BLUE = "\033[94m";
    static constexpr const char* COLOR_GRAY = "\033[90m";
    static constexpr const char* COLOR_WHITE = "\033[97m";
    static constexpr const char* COLOR_RED = "\033[91m";
    static constexpr const char* COLOR_BOLD = "\033[1m";
};

#endif // HEX_VIEWER_HPP
