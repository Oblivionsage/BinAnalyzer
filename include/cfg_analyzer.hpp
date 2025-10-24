#ifndef CFG_ANALYZER_HPP
#define CFG_ANALYZER_HPP

#include <vector>
#include <map>
#include "basic_block.hpp"
#include "function_analyzer.hpp"

namespace BinAnalyzer {

class CFGAnalyzer {
public:
    CFGAnalyzer() = default;
    
    void generate_cfg(const Function& func, const std::vector<BasicBlock>& blocks);
    void display_cfg(const Function& func, const std::vector<BasicBlock>& blocks);
    void print_statistics(const Function& func, const std::vector<BasicBlock>& blocks);
    
    // New loop detection functions
    std::vector<std::pair<uint64_t, uint64_t>> detect_loops(
        const Function& func, const std::vector<BasicBlock>& blocks);
    double get_average_complexity(const std::vector<Function>& functions);
    
private:
    std::map<uint64_t, std::vector<uint64_t>> adjacency_list;
};

} // namespace BinAnalyzer

#endif // CFG_ANALYZER_HPP
