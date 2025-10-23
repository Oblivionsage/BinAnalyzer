#ifndef DISASSEMBLER_HPP
#define DISASSEMBLER_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace BinAnalyzer {

struct Instruction {
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    size_t size;
};

class Disassembler {
public:
    explicit Disassembler(bool is_64bit = true);
    ~Disassembler();

    // Disassemble binary code
    std::vector<Instruction> disassemble(const uint8_t* code, size_t size, uint64_t base_address = 0);
    
    // Disassemble single instruction
    bool disassemble_single(const uint8_t* code, size_t size, uint64_t address, Instruction& out);

    // Set architecture mode
    void set_64bit_mode(bool enable);

private:
    void* handle;  // Capstone handle (opaque pointer)
    bool is_64bit;
};

} // namespace BinAnalyzer

#endif // DISASSEMBLER_HPP
