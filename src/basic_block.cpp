#include "basic_block.hpp"
#include <algorithm>
#include <sstream>

namespace BinAnalyzer {

bool BasicBlockAnalyzer::is_leader(const Instruction& inst, size_t index, 
                                     const std::vector<Instruction>& instructions) {
    // First instruction is always a leader
    if (index == 0) return true;
    
    // Target of jump/call is a leader
    for (size_t i = 0; i < instructions.size(); i++) {
        uint64_t target;
        if (extract_target_address(instructions[i], target)) {
            if (target == inst.address) return true;
        }
    }
    
    // Instruction after branch/call/return is a leader
    if (index > 0) {
        const auto& prev = instructions[index - 1];
        if (ends_block(prev)) return true;
    }
    
    return false;
}

bool BasicBlockAnalyzer::ends_block(const Instruction& inst) {
    // Returns
    if (inst.mnemonic == "ret" || inst.mnemonic == "retf" || 
        inst.mnemonic == "retn" || inst.mnemonic == "bx" ||
        (inst.mnemonic == "pop" && inst.operands.find("pc") != std::string::npos)) {
        return true;
    }
    
    // Unconditional jumps
    if (inst.mnemonic == "jmp" || inst.mnemonic == "b") {
        return true;
    }
    
    // Conditional jumps (block continues but also branches)
    if ((inst.mnemonic.length() >= 2 && inst.mnemonic[0] == 'j') ||
        (inst.mnemonic.length() >= 2 && inst.mnemonic[0] == 'b' && 
         inst.mnemonic != "bl" && inst.mnemonic != "blx")) {
        return true;
    }
    
    // System calls
    if (inst.mnemonic == "syscall" || inst.mnemonic == "sysenter" ||
        inst.mnemonic == "int" || inst.mnemonic == "svc") {
        return true;
    }
    
    return false;
}

bool BasicBlockAnalyzer::extract_target_address(const Instruction& inst, uint64_t& target) {
    // Simple heuristic: look for immediate addresses in operands
    std::string ops = inst.operands;
    
    // Remove common prefixes
    if (ops.find("0x") != std::string::npos) {
        size_t pos = ops.find("0x");
        std::string hex_str = ops.substr(pos + 2);
        
        // Extract hex digits only
        std::string clean_hex;
        for (char c : hex_str) {
            if (std::isxdigit(c)) {
                clean_hex += c;
            } else {
                break;
            }
        }
        
        if (!clean_hex.empty()) {
            try {
                target = std::stoull(clean_hex, nullptr, 16);
                return true;
            } catch (...) {
                return false;
            }
        }
    }
    
    return false;
}

std::vector<BasicBlock> BasicBlockAnalyzer::analyze(const std::vector<Instruction>& instructions) {
    if (instructions.empty()) return {};
    
    std::vector<BasicBlock> blocks;
    std::set<uint64_t> leaders;
    
    // Phase 1: Identify all leaders
    for (size_t i = 0; i < instructions.size(); i++) {
        if (is_leader(instructions[i], i, instructions)) {
            leaders.insert(instructions[i].address);
        }
    }
    
    // Phase 2: Create basic blocks
    BasicBlock* current_block = nullptr;
    
    for (const auto& inst : instructions) {
        // Start new block at leader
        if (leaders.count(inst.address)) {
            if (current_block) {
                current_block->end_address = current_block->instructions.back().address;
                blocks.push_back(*current_block);
            }
            current_block = new BasicBlock(inst.address);
        }
        
        if (current_block) {
            current_block->instructions.push_back(inst);
            current_block->end_address = inst.address;
            
            // Check block terminators
            if (inst.mnemonic == "ret" || inst.mnemonic == "bx") {
                current_block->ends_with_return = true;
            }
            if (inst.mnemonic == "call" || inst.mnemonic == "bl" || inst.mnemonic == "blx") {
                current_block->ends_with_call = true;
            }
            
            // End block if needed
            if (ends_block(inst)) {
                blocks.push_back(*current_block);
                current_block = nullptr;
            }
        }
    }
    
    // Add final block if exists
    if (current_block) {
        blocks.push_back(*current_block);
        delete current_block;
    }
    
    // Phase 3: Build successor/predecessor relationships
    for (auto& block : blocks) {
        const auto& last_inst = block.instructions.back();
        
        uint64_t target;
        if (extract_target_address(last_inst, target)) {
            block.successors.insert(target);
            
            // Find target block and add predecessor
            for (auto& other : blocks) {
                if (other.start_address == target) {
                    other.predecessors.insert(block.start_address);
                    break;
                }
            }
        }
        
        // Fall-through to next block (if not unconditional jump/return)
        if (last_inst.mnemonic != "jmp" && last_inst.mnemonic != "ret" &&
            last_inst.mnemonic != "b" && last_inst.mnemonic != "bx") {
            uint64_t next_addr = last_inst.address + last_inst.size;
            
            for (auto& other : blocks) {
                if (other.start_address == next_addr) {
                    block.successors.insert(next_addr);
                    other.predecessors.insert(block.start_address);
                    break;
                }
            }
        }
    }
    
    return blocks;
}

} // namespace BinAnalyzer
