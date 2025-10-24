#ifndef FUNCTION_ANALYZER_HPP
#define FUNCTION_ANALYZER_HPP

#include <vector>
#include <string>
#include <cstdint>
#include "disassembler.hpp"
#include "basic_block.hpp"

namespace BinAnalyzer {

struct Function {
    uint64_t start_address;
    uint64_t end_address;
    std::string name;
    std::vector<uint64_t> basic_blocks;
    std::set<uint64_t> call_sites;      // Addresses that call this function
    std::set<uint64_t> calls_to;        // Functions this one calls
    size_t instruction_count;
    bool has_prologue;
    bool has_epilogue;
    bool is_leaf;
    bool is_recursive;
    int complexity;
    std::string calling_convention;
};

class FunctionAnalyzer {
public:
    FunctionAnalyzer() = default;
    
    // Detect functions from instructions and basic blocks
    std::vector<Function> analyze(const std::vector<Instruction>& instructions,
                                   const std::vector<BasicBlock>& blocks);
    
    // Check if instruction sequence is a function prologue
    bool is_prologue(const std::vector<Instruction>& instructions, size_t start_idx);
    
    // Check if instruction is an epilogue pattern
    bool is_epilogue(const Instruction& inst);
    
    // Identify function boundaries
    void identify_function_boundaries(const std::vector<Instruction>& instructions,
                                      std::vector<Function>& functions);
};

} // namespace BinAnalyzer

#endif // FUNCTION_ANALYZER_HPP

    // Calculate cyclomatic complexity
    int calculate_complexity(const Function& func, const std::vector<BasicBlock>& blocks);
    
    // Detect calling convention
    std::string detect_calling_convention(const std::vector<Instruction>& instructions, size_t func_start);
    
    // Check if function is leaf (makes no calls)
    bool is_leaf_function(const Function& func);
    
    // Check if function is recursive
    bool is_recursive(const Function& func, const std::vector<Function>& all_functions);
