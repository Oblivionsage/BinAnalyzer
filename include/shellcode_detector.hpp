#ifndef SHELLCODE_DETECTOR_HPP
#define SHELLCODE_DETECTOR_HPP

#include <vector>
#include <string>
#include <cstdint>

enum class ShellcodeType {
    NONE, NOP_SLED, EGG_HUNTER, GETPC_CALL, GETPC_FNSTENV,
    METASPLOIT_PATTERN, REVERSE_SHELL, BIND_SHELL
};

struct ShellcodePattern {
    ShellcodeType type;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> mask;
    std::string description;
};

struct ShellcodeDetection {
    ShellcodeType type;
    uint32_t offset;
    size_t length;
    std::string description;
    double confidence;
};

struct ShellcodeAnalysisResult {
    std::vector<ShellcodeDetection> detections;
    bool shellcodeFound;
    int totalPatterns;
};

class ShellcodeDetector {
public:
    ShellcodeDetector();
    ShellcodeAnalysisResult analyze(const std::vector<uint8_t>& data);
    void displayResults(const ShellcodeAnalysisResult& result);

private:
    std::vector<ShellcodePattern> patterns_;
    
    void initializePatterns();
    bool matchPattern(const std::vector<uint8_t>& data, size_t offset,
                      const std::vector<uint8_t>& pattern,
                      const std::vector<uint8_t>& mask);
    bool detectNOPSled(const std::vector<uint8_t>& data, size_t offset);
};

#endif
