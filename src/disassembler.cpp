#include "disassembler.hpp"
#include <capstone/capstone.h>
#include <cstring>
#include <iostream>

namespace BinAnalyzer {

Disassembler::Disassembler(Architecture arch) : handle(nullptr), arch(arch) {
    initialize_engine();
}

Disassembler::~Disassembler() {
    cleanup_engine();
}

bool Disassembler::initialize_engine() {
    cleanup_engine();
    
    csh* cs_handle = new csh;
    cs_arch cs_architecture;
    cs_mode cs_mode_flags;
    
    // Map our architecture enum to Capstone
    switch (arch) {
        case Architecture::X86_32:
            cs_architecture = CS_ARCH_X86;
            cs_mode_flags = CS_MODE_32;
            break;
            
        case Architecture::X86_64:
            cs_architecture = CS_ARCH_X86;
            cs_mode_flags = CS_MODE_64;
            break;
            
        case Architecture::ARM_32:
            cs_architecture = CS_ARCH_ARM;
            cs_mode_flags = CS_MODE_ARM;
            break;
            
        case Architecture::ARM_64:
            cs_architecture = CS_ARCH_ARM64;
            cs_mode_flags = CS_MODE_ARM;
            break;
            
        case Architecture::THUMB:
            cs_architecture = CS_ARCH_ARM;
            cs_mode_flags = CS_MODE_THUMB;
            break;
            
        default:
            std::cerr << "[!] Invalid architecture" << std::endl;
            delete cs_handle;
            return false;
    }
    
    if (cs_open(cs_architecture, cs_mode_flags, cs_handle) != CS_ERR_OK) {
        std::cerr << "[!] Failed to initialize Capstone for architecture: " 
                  << architecture_to_string(arch) << std::endl;
        delete cs_handle;
        return false;
    }
    
    // Enable detail mode
    cs_option(*cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    handle = cs_handle;
    return true;
}

void Disassembler::cleanup_engine() {
    if (handle) {
        csh* cs_handle = static_cast<csh*>(handle);
        if (*cs_handle) {
            cs_close(cs_handle);
        }
        delete cs_handle;
        handle = nullptr;
    }
}

std::vector<Instruction> Disassembler::disassemble(const uint8_t* code, size_t size, uint64_t base_address) {
    std::vector<Instruction> instructions;
    
    if (!handle || !code || size == 0) {
        return instructions;
    }
    
    csh cs_handle = *static_cast<csh*>(handle);
    cs_insn* insn = nullptr;
    
    size_t count = cs_disasm(cs_handle, code, size, base_address, 0, &insn);
    
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            Instruction inst;
            inst.address = insn[i].address;
            inst.mnemonic = insn[i].mnemonic;
            inst.operands = insn[i].op_str;
            inst.size = insn[i].size;
            
            // Copy instruction bytes
            inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
            
            instructions.push_back(inst);
        }
        
        cs_free(insn, count);
    }
    
    return instructions;
}

bool Disassembler::disassemble_single(const uint8_t* code, size_t size, uint64_t address, Instruction& out) {
    if (!handle || !code || size == 0) {
        return false;
    }
    
    csh cs_handle = *static_cast<csh*>(handle);
    cs_insn* insn = nullptr;
    
    size_t count = cs_disasm(cs_handle, code, size, address, 1, &insn);
    
    if (count > 0) {
        out.address = insn[0].address;
        out.mnemonic = insn[0].mnemonic;
        out.operands = insn[0].op_str;
        out.size = insn[0].size;
        out.bytes.assign(insn[0].bytes, insn[0].bytes + insn[0].size);
        
        cs_free(insn, count);
        return true;
    }
    
    return false;
}

void Disassembler::set_architecture(Architecture new_arch) {
    if (arch != new_arch) {
        arch = new_arch;
        initialize_engine();
    }
}

Architecture Disassembler::get_architecture() const {
    return arch;
}

std::string architecture_to_string(Architecture arch) {
    switch (arch) {
        case Architecture::X86_32:  return "x86-32";
        case Architecture::X86_64:  return "x86-64";
        case Architecture::ARM_32:  return "ARM";
        case Architecture::ARM_64:  return "ARM64";
        case Architecture::THUMB:   return "ARM Thumb";
        case Architecture::AUTO:    return "Auto-detect";
        default:                     return "Unknown";
    }
}

Architecture string_to_architecture(const std::string& str) {
    if (str == "x86" || str == "x86-32" || str == "i386") 
        return Architecture::X86_32;
    if (str == "x64" || str == "x86-64" || str == "amd64") 
        return Architecture::X86_64;
    if (str == "arm" || str == "arm32") 
        return Architecture::ARM_32;
    if (str == "arm64" || str == "aarch64") 
        return Architecture::ARM_64;
    if (str == "thumb") 
        return Architecture::THUMB;
    
    return Architecture::AUTO;
}

} // namespace BinAnalyzer
