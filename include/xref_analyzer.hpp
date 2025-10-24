#ifndef XREF_ANALYZER_HPP
#define XREF_ANALYZER_HPP

#include <vector>
#include <map>
#include <set>
#include <string>
#include <cstdint>
#include "disassembler.hpp"

namespace BinAnalyzer {

struct CrossReference {
    uint64_t from_address;
    uint64_t to_address;
    std::string type;  // "call", "jump", "data"
};

class XRefAnalyzer {
public:
    XRefAnalyzer() = default;
    
    // Analyze cross-references
    std::vector<CrossReference> analyze(const std::vector<Instruction>& instructions);
    
    // Get all xrefs to a specific address
    std::vector<CrossReference> get_xrefs_to(uint64_t address);
    
    // Get all xrefs from a specific address
    std::vector<CrossReference> get_xrefs_from(uint64_t address);
    
    // Display xrefs for an address
    void display_xrefs(uint64_t address);
    
private:
    std::vector<CrossReference> xrefs;
    std::map<uint64_t, std::vector<CrossReference>> xrefs_to_map;
    std::map<uint64_t, std::vector<CrossReference>> xrefs_from_map;
    
    bool extract_address(const std::string& operands, uint64_t& addr);
    std::string determine_xref_type(const Instruction& inst);
};

} // namespace BinAnalyzer

#endif // XREF_ANALYZER_HPP
