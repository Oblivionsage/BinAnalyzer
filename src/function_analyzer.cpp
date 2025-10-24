// Function Boundary Detection Module
#include "function_analyzer.hpp"
#include <algorithm>

namespace BinAnalyzer {

bool FunctionAnalyzer::is_prologue(const std::vector<Instruction>& instructions, size_t start_idx) {
    if (start_idx + 2 >= instructions.size()) return false;
    
    const auto& inst1 = instructions[start_idx];
    const auto& inst2 = instructions[start_idx + 1];
    
    // x86/x64 patterns
    // push rbp/ebp; mov rbp/ebp, rsp/esp
    if (inst1.mnemonic == "push" && 
        (inst1.operands == "rbp" || inst1.operands == "ebp") &&
        inst2.mnemonic == "mov" &&
        (inst2.operands == "rbp, rsp" || inst2.operands == "ebp, esp")) {
        return true;
    }
    
    // ARM patterns
    // push {fp, lr} or stmfd sp!, {fp, lr}
    if (inst1.mnemonic == "push" && 
        (inst1.operands.find("fp") != std::string::npos ||
         inst1.operands.find("lr") != std::string::npos)) {
        return true;
    }
    
    // str fp, [sp, #-4]!
    if (inst1.mnemonic == "str" && inst1.operands.find("fp") != std::string::npos) {
        return true;
    }
    
    // sub rsp/esp, <value> (stack allocation)
    if (inst1.mnemonic == "sub" && 
        (inst1.operands.find("rsp") != std::string::npos ||
         inst1.operands.find("esp") != std::string::npos ||
         inst1.operands.find("sp") != std::string::npos)) {
        return true;
    }
    
    return false;
}

bool FunctionAnalyzer::is_epilogue(const Instruction& inst) {
    // Return instructions
    if (inst.mnemonic == "ret" || inst.mnemonic == "retf" || 
        inst.mnemonic == "retn" || inst.mnemonic == "bx") {
        return true;
    }
    
    // ARM: pop {pc} or ldm sp!, {pc}
    if (inst.mnemonic == "pop" && inst.operands.find("pc") != std::string::npos) {
        return true;
    }
    
    return false;
}

void FunctionAnalyzer::identify_function_boundaries(const std::vector<Instruction>& instructions,
                                                     std::vector<Function>& functions) {
    for (auto& func : functions) {
        // Find end by scanning forward for epilogue
        for (size_t i = 0; i < instructions.size(); i++) {
            if (instructions[i].address == func.start_address) {
                // Scan forward for return
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
    
    // Phase 1: Identify function entry points
    // Entry points are:
    // 1. First instruction (entry point)
    // 2. Call targets
    // 3. Instructions with prologue pattern
    
    std::set<uint64_t> function_starts;
    
    // Add first instruction
    if (!instructions.empty()) {
        function_starts.insert(instructions[0].address);
    }
    
    // Scan for prologues and call targets
    for (size_t i = 0; i < instructions.size(); i++) {
        const auto& inst = instructions[i];
        
        // Check for prologue
        if (is_prologue(instructions, i)) {
            function_starts.insert(inst.address);
        }
        
        // Check for call instruction - target is a function
        if (inst.mnemonic == "call" || inst.mnemonic == "bl" || 
            inst.mnemonic == "blx") {
            // Extract target from operands (simple heuristic)
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
    
    // Phase 2: Create function objects
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
        
        // Check if it has prologue
        for (size_t i = 0; i < instructions.size(); i++) {
            if (instructions[i].address == addr) {
                func.has_prologue = is_prologue(instructions, i);
                break;
            }
        }
        
        // Associate basic blocks
        for (const auto& block : blocks) {
            if (block.start_address >= addr) {
                func.basic_blocks.push_back(block.start_address);
            }
        }
        
        functions.push_back(func);
    }
    
    // Phase 3: Identify boundaries and relationships
    identify_function_boundaries(instructions, functions);
    
    // Phase 4: Build call graph
    for (const auto& inst : instructions) {
        if (inst.mnemonic == "call" || inst.mnemonic == "bl" || 
            inst.mnemonic == "blx") {
            
            // Find which function this call is in
            for (auto& func : functions) {
                if (inst.address >= func.start_address && 
                    inst.address <= func.end_address) {
                    
                    // Extract call target
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
                                
                                // Add to target's call_sites
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
    
    return functions;
}

} // namespace BinAnalyzer

// TODO: Detect nested functions
// TODO: Add function signature analysis
// TODO: Support stack frame reconstruction

bool FunctionAnalyzer::is_leaf_function(const Function& func) {
    // Leaf function makes no calls to other functions
    return func.calls_to.empty();
}

// Note: Recursive detection checks both direct and indirect recursion

bool FunctionAnalyzer::is_recursive(const Function& func, const std::vector<Function>& all_functions) {
    // Direct recursion: function calls itself
    if (func.calls_to.count(func.start_address)) {
        return true;
    }
    
    // Indirect recursion: check if any called function eventually calls back
    // For simplicity, only check one level deep
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
    // Cyclomatic Complexity = E - N + 2P
    // E = edges, N = nodes, P = connected components (usually 1)
    // Simplified: M = E - N + 2
    
    int nodes = 0;
    int edges = 0;
    
    for (const auto& block : blocks) {
        // Count blocks in this function
        if (block.start_address >= func.start_address && 
            block.start_address <= func.end_address) {
            nodes++;
            edges += block.successors.size();
        }
    }
    
    if (nodes == 0) return 1;
    
    // M = E - N + 2
    int complexity = edges - nodes + 2;
    return (complexity > 0) ? complexity : 1;
}

// TODO: Add support for switch statements in complexity calculation
// TODO: Implement McCabe's extension for nested complexity

std::string FunctionAnalyzer::detect_calling_convention(const std::vector<Instruction>& instructions, size_t func_start) {
    // Check first few instructions for calling convention patterns
    std::vector<std::string> registers_used;
    bool stack_cleanup = false;
    
    for (size_t i = func_start; i < std::min(func_start + 10, instructions.size()); i++) {
        const auto& inst = instructions[i];
        
        // x64: fastcall uses rcx, rdx, r8, r9
        if (inst.operands.find("rcx") != std::string::npos ||
            inst.operands.find("rdx") != std::string::npos ||
            inst.operands.find("r8") != std::string::npos ||
            inst.operands.find("r9") != std::string::npos) {
            return "fastcall (x64)";
        }
        
        // x86: fastcall uses ecx, edx
        if (inst.operands.find("ecx") != std::string::npos ||
            inst.operands.find("edx") != std::string::npos) {
            return "fastcall (x86)";
        }
        
        // Check for stack cleanup (stdcall)
        if (inst.mnemonic == "ret" && !inst.operands.empty()) {
            return "stdcall";
        }
    }
    
    // Default
    return "cdecl";
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

// Note: Complexity calculation follows McCabe's cyclomatic complexity metric
