#include "disassembler.hpp"
#include <capstone/capstone.h>
#include <cstring>
#include <iostream>

namespace BinAnalyzer {

Disassembler::Disassembler(bool is_64bit) : handle(nullptr), is_64bit(is_64bit) {
    csh* cs_handle = new csh;
    
    cs_mode mode = is_64bit ? CS_MODE_64 : CS_MODE_32;
    
    if (cs_open(CS_ARCH_X86, mode, cs_handle) != CS_ERR_OK) {
        std::cerr << "[!] Failed to initialize Capstone engine" << std::endl;
        delete cs_handle;
        cs_handle = nullptr;
    }
    
    // Enable detail mode for more info
    if (cs_handle && *cs_handle) {
        cs_option(*cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
    
    handle = cs_handle;
}

Disassembler::~Disassembler() {
    if (handle) {
        csh* cs_handle = static_cast<csh*>(handle);
        if (*cs_handle) {
            cs_close(cs_handle);
        }
        delete cs_handle;
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

void Disassembler::set_64bit_mode(bool enable) {
    if (!handle) return;
    
    is_64bit = enable;
    
    csh* cs_handle = static_cast<csh*>(handle);
    if (*cs_handle) {
        cs_close(cs_handle);
    }
    
    cs_mode mode = is_64bit ? CS_MODE_64 : CS_MODE_32;
    cs_open(CS_ARCH_X86, mode, cs_handle);
    cs_option(*cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

} // namespace BinAnalyzer
