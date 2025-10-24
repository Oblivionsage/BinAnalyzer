// Copyright (c) 2024-2025 Oblivionsage
#ifndef DISASSEMBLER_HPP
#define DISASSEMBLER_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace BinAnalyzer {

enum class Architecture {
    X86_32,
    X86_64,
    ARM_32,
    ARM_64,
    THUMB,      // ARM Thumb mode
    AUTO        // Auto-detect
};

struct Instruction {
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    size_t size;
};

class Disassembler {
public:
    explicit Disassembler(Architecture arch = Architecture::X86_64);
    ~Disassembler();

    // Disassemble binary code
    std::vector<Instruction> disassemble(const uint8_t* code, size_t size, uint64_t base_address = 0);
    
    // Disassemble single instruction
    bool disassemble_single(const uint8_t* code, size_t size, uint64_t address, Instruction& out);

    // Set architecture
    void set_architecture(Architecture arch);
    
    // Get current architecture
    Architecture get_architecture() const;

private:
    void* handle;  // Capstone handle (opaque pointer)
    Architecture arch;
    
    bool initialize_engine();
    void cleanup_engine();
};

// Helper functions
std::string architecture_to_string(Architecture arch);
Architecture string_to_architecture(const std::string& str);

} // namespace BinAnalyzer

#endif // DISASSEMBLER_HPP
