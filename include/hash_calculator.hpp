#ifndef HASH_CALCULATOR_HPP
#define HASH_CALCULATOR_HPP

#include <string>
#include <vector>
#include <cstdint>

class HashCalculator {
public:
    static std::string calculateMD5(const std::vector<uint8_t>& data);
    static std::string calculateSHA256(const std::vector<uint8_t>& data);
    
    static std::string calculateMD5FromFile(const std::string& filename);
    static std::string calculateSHA256FromFile(const std::string& filename);

private:
    static std::string bytesToHexString(const unsigned char* data, size_t length);
};

#endif // HASH_CALCULATOR_HPP
