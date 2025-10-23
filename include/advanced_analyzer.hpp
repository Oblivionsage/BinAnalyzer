#ifndef ADVANCED_ANALYZER_HPP
#define ADVANCED_ANALYZER_HPP

#include "packer_detector.hpp"
#include "shellcode_detector.hpp"
#include "ioc_extractor.hpp"
#include "string_analyzer.hpp"

class AdvancedAnalyzer {
public:
    AdvancedAnalyzer();
    void runFullAnalysis(const std::vector<uint8_t>& data);

private:
    PackerDetector packerDetector_;
    ShellcodeDetector shellcodeDetector_;
    IOCExtractor iocExtractor_;
    StringAnalyzer stringAnalyzer_;
};

#endif
