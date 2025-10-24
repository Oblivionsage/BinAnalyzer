#include "xref_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>

namespace BinAnalyzer {

bool XRefAnalyzer::extract_address(const std::string& operands, uint64_t& addr) {
    if (operands.find("0x") == std::string::npos) {
        return false;
    }
    
    size_t pos = operands.find("0x");
    std::string hex_str = operands.substr(pos + 2);
    
    std::string clean_hex;
    for (char c : hex_str) {
        if (std::isxdigit(c)) {
            clean_hex += c;
        } else {
            break;
        }
    }
    
    if (clean_hex.empty()) return false;
    
    try {
        addr = std::stoull(clean_hex, nullptr, 16);
        return true;
    } catch (...) {
        return false;
    }
}

std::string XRefAnalyzer::determine_xref_type(const Instruction& inst) {
    if (inst.mnemonic == "call" || inst.mnemonic == "bl" || inst.mnemonic == "blx") {
        return "call";
    }
    
    if (inst.mnemonic[0] == 'j' || 
        (inst.mnemonic[0] == 'b' && inst.mnemonic != "bl" && inst.mnemonic != "blx")) {
        return "jump";
    }
    
    if (inst.mnemonic == "lea" || inst.mnemonic == "mov" || 
        inst.mnemonic == "ldr" || inst.mnemonic == "str") {
        return "data";
    }
    
    return "ref";
}

std::vector<CrossReference> XRefAnalyzer::analyze(const std::vector<Instruction>& instructions) {
    xrefs.clear();
    xrefs_to_map.clear();
    xrefs_from_map.clear();
    
    for (const auto& inst : instructions) {
        uint64_t target;
        if (extract_address(inst.operands, target)) {
            CrossReference xref;
            xref.from_address = inst.address;
            xref.to_address = target;
            xref.type = determine_xref_type(inst);
            
            xrefs.push_back(xref);
            xrefs_to_map[target].push_back(xref);
            xrefs_from_map[inst.address].push_back(xref);
        }
    }
    
    return xrefs;
}

std::vector<CrossReference> XRefAnalyzer::get_xrefs_to(uint64_t address) {
    if (xrefs_to_map.count(address)) {
        return xrefs_to_map[address];
    }
    return {};
}

std::vector<CrossReference> XRefAnalyzer::get_xrefs_from(uint64_t address) {
    if (xrefs_from_map.count(address)) {
        return xrefs_from_map[address];
    }
    return {};
}

void XRefAnalyzer::display_xrefs(uint64_t address) {
    auto to_refs = get_xrefs_to(address);
    auto from_refs = get_xrefs_from(address);
    
    if (!to_refs.empty()) {
        std::cout << "[*] Cross-references TO 0x" << std::hex << address << std::dec << "\n";
        std::cout << "-------------------------------\n";
        
        for (const auto& xref : to_refs) {
            std::cout << "  0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << xref.from_address << std::dec;
            
            if (xref.type == "call") {
                std::cout << " \033[91m(CALL)\033[0m\n";
            } else if (xref.type == "jump") {
                std::cout << " \033[93m(JUMP)\033[0m\n";
            } else {
                std::cout << " (" << xref.type << ")\n";
            }
        }
        std::cout << "\n";
    }
    
    if (!from_refs.empty()) {
        std::cout << "[*] Cross-references FROM 0x" << std::hex << address << std::dec << "\n";
        std::cout << "--------------------------------\n";
        
        for (const auto& xref : from_refs) {
            std::cout << "  0x" << std::hex << std::setw(8) << std::setfill('0') 
                      << xref.to_address << std::dec;
            
            if (xref.type == "call") {
                std::cout << " \033[91m(CALL)\033[0m\n";
            } else if (xref.type == "jump") {
                std::cout << " \033[93m(JUMP)\033[0m\n";
            } else {
                std::cout << " (" << xref.type << ")\n";
            }
        }
        std::cout << "\n";
    }
    
    if (to_refs.empty() && from_refs.empty()) {
        std::cout << "No cross-references found for 0x" << std::hex << address << std::dec << "\n\n";
    }
}

} // namespace BinAnalyzer
