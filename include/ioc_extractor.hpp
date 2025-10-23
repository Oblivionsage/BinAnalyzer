#ifndef IOC_EXTRACTOR_HPP
#define IOC_EXTRACTOR_HPP

#include <vector>
#include <string>
#include <map>
#include <cstdint>

enum class IOCType {
    IPV4_ADDRESS, IPV6_ADDRESS, URL_ADDRESS,
    DOMAIN_NAME, EMAIL_ADDRESS, BITCOIN_ADDRESS
};

struct NetworkIOC {
    IOCType type;
    std::string value;
    uint32_t offset;
    std::string context;
};

struct IOCExtractionResult {
    std::vector<NetworkIOC> iocs;
    std::map<IOCType, int> counts;
    bool networkActivitySuspected;
};

class IOCExtractor {
public:
    IOCExtractor();
    IOCExtractionResult extract(const std::vector<uint8_t>& data);
    void displayResults(const IOCExtractionResult& result);

private:
    bool isValidIPv4(const std::string& str);
    bool isValidDomain(const std::string& str);
    bool isValidEmail(const std::string& str);
    std::string extractContext(const std::vector<uint8_t>& data, size_t offset, size_t length);
    std::string getIOCTypeName(IOCType type);
};

#endif
