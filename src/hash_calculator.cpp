#include "hash_calculator.hpp"
#include <openssl/evp.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cstring>

std::string HashCalculator::calculateMD5(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    
    EVP_DigestInit_ex(context, md, nullptr);
    EVP_DigestUpdate(context, data.data(), data.size());
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    
    EVP_MD_CTX_free(context);
    
    return bytesToHexString(hash, lengthOfHash);
}

std::string HashCalculator::calculateSHA256(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    
    EVP_DigestInit_ex(context, md, nullptr);
    EVP_DigestUpdate(context, data.data(), data.size());
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    
    EVP_MD_CTX_free(context);
    
    return bytesToHexString(hash, lengthOfHash);
}

std::string HashCalculator::calculateMD5FromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for MD5 calculation");
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    
    EVP_DigestInit_ex(context, md, nullptr);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        EVP_DigestUpdate(context, buffer, file.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    
    EVP_MD_CTX_free(context);
    
    return bytesToHexString(hash, lengthOfHash);
}

std::string HashCalculator::calculateSHA256FromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for SHA256 calculation");
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    
    EVP_DigestInit_ex(context, md, nullptr);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        EVP_DigestUpdate(context, buffer, file.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    
    EVP_MD_CTX_free(context);
    
    return bytesToHexString(hash, lengthOfHash);
}

std::string HashCalculator::bytesToHexString(const unsigned char* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}
