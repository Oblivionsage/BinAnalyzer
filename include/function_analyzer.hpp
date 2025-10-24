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
    std::set<uint64_t> call_sites;
    std::set<uint64_t> calls_to;
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
    
    std::vector<Function> analyze(const std::vector<Instruction>& instructions,
                                   const std::vector<BasicBlock>& blocks);
    
    bool is_prologue(const std::vector<Instruction>& instructions, size_t start_idx);
    bool is_epilogue(const Instruction& inst);
    void identify_function_boundaries(const std::vector<Instruction>& instructions,
                                      std::vector<Function>& functions);
    
    // New metrics functions
    int calculate_complexity(const Function& func, const std::vector<BasicBlock>& blocks);
    std::string detect_calling_convention(const std::vector<Instruction>& instructions, size_t func_start);
    bool is_leaf_function(const Function& func);
    bool is_recursive(const Function& func, const std::vector<Function>& all_functions);
};

} // namespace BinAnalyzer

#endif // FUNCTION_ANALYZER_HPP
