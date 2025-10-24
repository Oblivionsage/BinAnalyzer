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
    
    // Generate control flow graph for a function
    void generate_cfg(const Function& func, const std::vector<BasicBlock>& blocks);
    
    // Display CFG in minimal ASCII art
    void display_cfg(const Function& func, const std::vector<BasicBlock>& blocks);
    
    // Get CFG statistics
    void print_statistics(const Function& func, const std::vector<BasicBlock>& blocks);
    
private:
    std::map<uint64_t, std::vector<uint64_t>> adjacency_list;
};

} // namespace BinAnalyzer

#endif // CFG_ANALYZER_HPP

