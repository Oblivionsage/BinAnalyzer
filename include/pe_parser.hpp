#ifndef PE_PARSER_HPP
#define PE_PARSER_HPP

#include <vector>
#include <cstdint>
#include <string>

struct PEInfo {
    bool isPE;
    std::string architecture;  // x86, x64
    std::string subsystem;     // Console, GUI
    uint32_t entryPoint;
    uint32_t imageBase;
    uint32_t numberOfSections;
    uint32_t timestamp;
    std::vector<std::string> sections;
};

class PEParser {
public:
    PEParser();
    
    PEInfo parse(const std::vector<uint8_t>& data);
    bool isPEFile(const std::vector<uint8_t>& data);
    
    std::vector<std::string> extractStrings(const std::vector<uint8_t>& data, size_t minLength = 4);

private:
    bool isValidPESignature(const std::vector<uint8_t>& data);
    uint32_t getPEHeaderOffset(const std::vector<uint8_t>& data);
    bool isPrintable(uint8_t c);
};

#endif // PE_PARSER_HPP
