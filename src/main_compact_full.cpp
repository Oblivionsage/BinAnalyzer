// Compact two-column output design - AFL style

void print_compact_header() {
    std::cout << "\n";
    std::cout << "\033[1;96m  BinAnalyzer v1.0\033[0m - Binary Analysis Tool\n";
    std::cout << "  ════════════════════════════════════════════════════════════════════════════\n\n";
}

void print_compact_summary(const std::string& filepath, size_t filesize, 
                          const std::string& md5, const std::string& sha256,
                          const std::string& filetype, double entropy,
                          uint64_t entryPoint, const std::string& arch,
                          const std::vector<BinAnalyzer::Instruction>& instructions,
                          const std::vector<BinAnalyzer::BasicBlock>& blocks,
                          const std::vector<BinAnalyzer::Function>& functions,
                          const std::vector<BinAnalyzer::XRef>& xrefs,
                          size_t null_bytes, size_t printable, size_t control, size_t extended,
                          size_t total_strings) {
    
    // Calculate stats
    int leaf_count = 0, recursive_count = 0, complex_count = 0;
    int call_xrefs = 0, jump_xrefs = 0, data_xrefs = 0, total_loops = 0;
    int max_complexity = 0;
    
    for (const auto& func : functions) {
        if (func.is_leaf) leaf_count++;
        if (func.is_recursive) recursive_count++;
        if (func.complexity > 10) complex_count++;
        if (func.complexity > max_complexity) max_complexity = func.complexity;
        
        BinAnalyzer::CFGAnalyzer cfgAnalyzer;
        auto loops = cfgAnalyzer.detect_loops(func, blocks);
        total_loops += loops.size();
    }
    
    for (const auto& xref : xrefs) {
        if (xref.type == "call") call_xrefs++;
        else if (xref.type == "jump") jump_xrefs++;
        else data_xrefs++;
    }
    
    double avg_complexity = 0.0;
    if (!functions.empty()) {
        BinAnalyzer::CFGAnalyzer cfgAnalyzer;
        avg_complexity = cfgAnalyzer.get_average_complexity(functions);
    }
    
    double null_pct = (null_bytes * 100.0) / filesize;
    double print_pct = (printable * 100.0) / filesize;
    
    // Get filename only
    std::string filename = filepath.substr(filepath.find_last_of("/\\") + 1);
    
    std::cout << "  ┌───────────── \033[96mfile information\033[0m ────────────┬─────────── \033[96mbyte analysis\033[0m ───────────┐\n";
    std::cout << "  │ Target      : " << std::left << std::setw(30) << filename.substr(0, 30)
              << "│ NULL bytes  : " << std::setw(5) << std::fixed << std::setprecision(1) << null_pct << "% │\n";
    std::cout << "  │ Size        : " << std::setw(20) << (filesize / 1024) << " KB      "
              << "│ Printable   : " << std::setw(5) << print_pct << "% │\n";
    std::cout << "  │ Type        : " << std::setw(30) << filetype
              << "│ Entropy     : " << std::setw(5) << entropy << "/8 │\n";
    std::cout << "  │ MD5         : " << md5.substr(0, 16) << "...   "
              << "│ Strings     : " << std::setw(7) << total_strings << "   │\n";
    std::cout << "  ├───────────── \033[96mcode analysis\033[0m ──────────────┼─────────── \033[96mcontrol flow\033[0m ───────────┤\n";
    std::cout << "  │ Architecture: " << std::setw(30) << arch
              << "│ Functions   : " << std::setw(7) << functions.size() << "   │\n";
    std::cout << "  │ Entry point : 0x" << std::hex << std::setw(28) << entryPoint << std::dec
              << "│   - Leaf    : " << std::setw(7) << leaf_count << "   │\n";
    std::cout << "  │ Instructions: " << std::setw(30) << instructions.size()
              << "│   - Recursive:" << std::setw(6) << recursive_count << "   │\n";
    std::cout << "  │ Basic blocks: " << std::setw(30) << blocks.size()
              << "│   - Complex : " << std::setw(7) << complex_count << "   │\n";
    std::cout << "  ├──────────────────────────────────────┼──────────────────────────────────────┤\n";
    std::cout << "  │ Cross-refs  : " << std::setw(30) << xrefs.size()
              << "│ Loops       : " << std::setw(7) << total_loops << "   │\n";
    std::cout << "  │   - Calls   : " << std::setw(30) << call_xrefs
              << "│ Avg complex.: " << std::fixed << std::setprecision(1) << std::setw(7) << avg_complexity << "   │\n";
    std::cout << "  │   - Jumps   : " << std::setw(30) << jump_xrefs
              << "│ Max complex.: " << std::setw(7) << max_complexity << "   │\n";
    std::cout << "  │   - Data    : " << std::setw(30) << data_xrefs
              << "│ CFG edges   : " << std::setw(7) << (call_xrefs + jump_xrefs) << "   │\n";
    std::cout << "  └──────────────────────────────────────┴──────────────────────────────────────┘\n";
    std::cout << "  \033[90m Use --disasm, --functions, --blocks, --cfg, --xref <addr> for details\033[0m\n\n";
}
