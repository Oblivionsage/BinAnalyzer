#include "function_analyzer.hpp"
#include <algorithm>

namespace BinAnalyzer {

bool FunctionAnalyzer::is_prologue(const std::vector<Instruction>& instructions, size_t start_idx) {
    if (start_idx + 2 >= instructions.size()) return false;
    
    const auto& inst1 = instructions[start_idx];
    const auto& inst2 = instructions[start_idx + 1];
    
    // x86/x64 patterns
    if (inst1.mnemonic == "push" && 
        (inst1.operands == "rbp" || inst1.operands == "ebp") &&
        inst2.mnemonic == "mov" &&
        (inst2.operands == "rbp, rsp" || inst2.operands == "ebp, esp")) {
        return true;
    }
    
    // ARM patterns
    if (inst1.mnemonic == "push" && 
        (inst1.operands.find("fp") != std::string::npos ||
         inst1.operands.find("lr") != std::string::npos)) {
        return true;
    }
    
    if (inst1.mnemonic == "str" && inst1.operands.find("fp") != std::string::npos) {
        return true;
    }
    
    if (inst1.mnemonic == "sub" && 
        (inst1.operands.find("rsp") != std::string::npos ||
         inst1.operands.find("esp") != std::string::npos ||
         inst1.operands.find("sp") != std::string::npos)) {
        return true;
    }
    
    return false;
}

bool FunctionAnalyzer::is_epilogue(const Instruction& inst) {
    if (inst.mnemonic == "ret" || inst.mnemonic == "retf" || 
        inst.mnemonic == "retn" || inst.mnemonic == "bx") {
        return true;
    }
    
    if (inst.mnemonic == "pop" && inst.operands.find("pc") != std::string::npos) {
        return true;
    }
    
    return false;
}

void FunctionAnalyzer::identify_function_boundaries(const std::vector<Instruction>& instructions,
                                                     std::vector<Function>& functions) {
    for (auto& func : functions) {
        for (size_t i = 0; i < instructions.size(); i++) {
            if (instructions[i].address == func.start_address) {
                for (size_t j = i; j < instructions.size() && j < i + 1000; j++) {
                    if (is_epilogue(instructions[j])) {
                        func.end_address = instructions[j].address;
                        func.instruction_count = j - i + 1;
                        func.has_epilogue = true;
                        break;
                    }
                }
                break;
            }
        }
    }
}

std::vector<Function> FunctionAnalyzer::analyze(const std::vector<Instruction>& instructions,
                                                 const std::vector<BasicBlock>& blocks) {
    std::vector<Function> functions;
    std::set<uint64_t> function_starts;
    
    if (!instructions.empty()) {
        function_starts.insert(instructions[0].address);
    }
    
    for (size_t i = 0; i < instructions.size(); i++) {
        const auto& inst = instructions[i];
        
        if (is_prologue(instructions, i)) {
            function_starts.insert(inst.address);
        }
        
        if (inst.mnemonic == "call" || inst.mnemonic == "bl" || 
            inst.mnemonic == "blx") {
            if (inst.operands.find("0x") != std::string::npos) {
                size_t pos = inst.operands.find("0x");
                std::string hex_str = inst.operands.substr(pos + 2);
                
                std::string clean_hex;
                for (char c : hex_str) {
                    if (std::isxdigit(c)) clean_hex += c;
                    else break;
                }
                
                if (!clean_hex.empty()) {
                    try {
                        uint64_t target = std::stoull(clean_hex, nullptr, 16);
                        function_starts.insert(target);
                    } catch (...) {}
                }
            }
        }
    }
    
    for (uint64_t addr : function_starts) {
        Function func;
        func.start_address = addr;
        func.end_address = addr;
        func.instruction_count = 0;
        func.has_prologue = false;
        func.has_epilogue = false;
        func.is_leaf = false;
        func.is_recursive = false;
        func.complexity = 1;
        func.calling_convention = "unknown";
        func.name = "sub_" + std::to_string(addr);
        
        for (size_t i = 0; i < instructions.size(); i++) {
            if (instructions[i].address == addr) {
                func.has_prologue = is_prologue(instructions, i);
                break;
            }
        }
        
        for (const auto& block : blocks) {
            if (block.start_address >= addr) {
                func.basic_blocks.push_back(block.start_address);
            }
        }
        
        functions.push_back(func);
    }
    
    identify_function_boundaries(instructions, functions);
    
    for (const auto& inst : instructions) {
        if (inst.mnemonic == "call" || inst.mnemonic == "bl" || 
            inst.mnemonic == "blx") {
            
            for (auto& func : functions) {
                if (inst.address >= func.start_address && 
                    inst.address <= func.end_address) {
                    
                    if (inst.operands.find("0x") != std::string::npos) {
                        size_t pos = inst.operands.find("0x");
                        std::string hex_str = inst.operands.substr(pos + 2);
                        
                        std::string clean_hex;
                        for (char c : hex_str) {
                            if (std::isxdigit(c)) clean_hex += c;
                            else break;
                        }
                        
                        if (!clean_hex.empty()) {
                            try {
                                uint64_t target = std::stoull(clean_hex, nullptr, 16);
                                func.calls_to.insert(target);
                                
                                for (auto& target_func : functions) {
                                    if (target_func.start_address == target) {
                                        target_func.call_sites.insert(func.start_address);
                                        break;
                                    }
                                }
                            } catch (...) {}
                        }
                    }
                    break;
                }
            }
        }
    }
    
    // Phase 5: Calculate function metrics
    for (auto& func : functions) {
        func.is_leaf = is_leaf_function(func);
        func.is_recursive = is_recursive(func, functions);
        func.complexity = calculate_complexity(func, blocks);
        
        for (size_t i = 0; i < instructions.size(); i++) {
            if (instructions[i].address == func.start_address) {
                func.calling_convention = detect_calling_convention(instructions, i);
                break;
            }
        }
    }
    
    return functions;
}

bool FunctionAnalyzer::is_leaf_function(const Function& func) {
    return func.calls_to.empty();
}

bool FunctionAnalyzer::is_recursive(const Function& func, const std::vector<Function>& all_functions) {
    if (func.calls_to.count(func.start_address)) {
        return true;
    }
    
    for (uint64_t called_addr : func.calls_to) {
        for (const auto& other_func : all_functions) {
            if (other_func.start_address == called_addr) {
                if (other_func.calls_to.count(func.start_address)) {
                    return true;
                }
                break;
            }
        }
    }
    
    return false;
}

int FunctionAnalyzer::calculate_complexity(const Function& func, const std::vector<BasicBlock>& blocks) {
    int nodes = 0;
    int edges = 0;
    
    for (const auto& block : blocks) {
        if (block.start_address >= func.start_address && 
            block.start_address <= func.end_address) {
            nodes++;
            edges += block.successors.size();
        }
    }
    
    if (nodes == 0) return 1;
    
    int complexity = edges - nodes + 2;
    return (complexity > 0) ? complexity : 1;
}

std::string FunctionAnalyzer::detect_calling_convention(const std::vector<Instruction>& instructions, size_t func_start) {
    for (size_t i = func_start; i < std::min(func_start + 10, instructions.size()); i++) {
        const auto& inst = instructions[i];
        
        if (inst.operands.find("rcx") != std::string::npos ||
            inst.operands.find("rdx") != std::string::npos ||
            inst.operands.find("r8") != std::string::npos ||
            inst.operands.find("r9") != std::string::npos) {
            return "fastcall (x64)";
        }
        
        if (inst.operands.find("ecx") != std::string::npos ||
            inst.operands.find("edx") != std::string::npos) {
            return "fastcall (x86)";
        }
        
        if (inst.mnemonic == "ret" && !inst.operands.empty()) {
            return "stdcall";
        }
    }
    
    return "cdecl";
}

// Note: Complexity calculation follows McCabe's cyclomatic complexity metric

} // namespace BinAnalyzer
