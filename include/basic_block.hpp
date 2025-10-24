#ifndef BASIC_BLOCK_HPP
#define BASIC_BLOCK_HPP

#include <vector>
#include <set>
#include <cstdint>
#include "disassembler.hpp"

namespace BinAnalyzer {

class BasicBlock {
public:
    uint64_t start_address;
    uint64_t end_address;
    std::vector<Instruction> instructions;
    std::set<uint64_t> successors;      // Addresses of following blocks
    std::set<uint64_t> predecessors;    // Addresses of incoming blocks
    bool is_function_entry;
    bool ends_with_return;
    bool ends_with_call;
    
    BasicBlock(uint64_t start) : 
        start_address(start), 
        end_address(start),
        is_function_entry(false),
        ends_with_return(false),
        ends_with_call(false) {}
        , block_type(NORMAL)
        , loop_depth(0)
    
    size_t size() const { return instructions.size(); }
    bool contains(uint64_t addr) const {
        return addr >= start_address && addr <= end_address;
    }
};

class BasicBlockAnalyzer {
public:
    BasicBlockAnalyzer() = default;
    
    // Identify basic blocks from instructions
    std::vector<BasicBlock> analyze(const std::vector<Instruction>& instructions);
    
    // Check if instruction is a leader (starts a new block)
    bool is_leader(const Instruction& inst, size_t index, 
                   const std::vector<Instruction>& instructions);
    
    // Check if instruction ends a block
    bool ends_block(const Instruction& inst);
    
    // Extract jump/call target address
    bool extract_target_address(const Instruction& inst, uint64_t& target);
};

} // namespace BinAnalyzer

#endif // BASIC_BLOCK_HPP

    enum BlockType {
        NORMAL,
        ENTRY,
        EXIT,
        LOOP_HEADER
    };
    
    BlockType block_type;
    int loop_depth;
