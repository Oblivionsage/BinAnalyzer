// BinAnalyzer - CFG Analysis Module
#include "cfg_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>

namespace BinAnalyzer {

void CFGAnalyzer::generate_cfg(const Function& func, const std::vector<BasicBlock>& blocks) {
    adjacency_list.clear();
    
    // Build adjacency list from basic blocks in this function
    for (const auto& block : blocks) {
        if (block.start_address >= func.start_address && 
            block.start_address <= func.end_address) {
            
            for (uint64_t succ : block.successors) {
                adjacency_list[block.start_address].push_back(succ);
            }
        }
    }
}

void CFGAnalyzer::display_cfg(const Function& func, const std::vector<BasicBlock>& blocks) {
    std::cout << "[*] Control Flow Graph\n";
    std::cout << "----------------------\n";
    std::cout << "Function: " << func.name << " @ 0x" << std::hex << func.start_address << std::dec << "\n\n";
    
    // Simple ASCII representation
    for (const auto& block : blocks) {
        if (block.start_address < func.start_address || 
            block.start_address > func.end_address) {
            continue;
        }
        
        std::cout << "  [0x" << std::hex << std::setw(8) << std::setfill('0') 
                  << block.start_address << std::dec << "]";
        
        if (block.is_function_entry) {
            std::cout << " \033[92m(ENTRY)\033[0m";
        }
        if (block.ends_with_return) {
            std::cout << " \033[91m(RET)\033[0m";
        }
        
        std::cout << "\n";
        std::cout << "    Instructions: " << block.size() << "\n";
        
        if (!block.successors.empty()) {
            std::cout << "    Successors: ";
            for (uint64_t succ : block.successors) {
                std::cout << "0x" << std::hex << succ << std::dec << " ";
            }
            std::cout << "\n";
        }
        
        if (!block.predecessors.empty()) {
            std::cout << "    Predecessors: ";
            for (uint64_t pred : block.predecessors) {
                std::cout << "0x" << std::hex << pred << std::dec << " ";
            }
            std::cout << "\n";
        }
        
        std::cout << "\n";
    }
}

void CFGAnalyzer::print_statistics(const Function& func, const std::vector<BasicBlock>& blocks) {
    size_t block_count = 0;
    size_t edge_count = 0;
    size_t entry_blocks = 0;
    size_t exit_blocks = 0;
    
    for (const auto& block : blocks) {
        if (block.start_address >= func.start_address && 
            block.start_address <= func.end_address) {
            block_count++;
            edge_count += block.successors.size();
            
            if (block.is_function_entry || block.predecessors.empty()) {
                entry_blocks++;
            }
            if (block.ends_with_return || block.successors.empty()) {
                exit_blocks++;
            }
        }
    }
    
    std::cout << "[*] CFG Statistics\n";
    std::cout << "------------------\n";
    std::cout << "Basic blocks:  " << block_count << "\n";
    std::cout << "Edges:         " << edge_count << "\n";
    std::cout << "Entry blocks:  " << entry_blocks << "\n";
    std::cout << "Exit blocks:   " << exit_blocks << "\n";
    
    if (block_count > 0) {
        std::cout << "Avg edges/block: " << std::fixed << std::setprecision(2) 
                  << (double)edge_count / block_count << "\n";
    }
    
    std::cout << "\n";
}

} // namespace BinAnalyzer

