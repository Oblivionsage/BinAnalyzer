#include "cli_parser.hpp"
#include <iostream>
#include <cstring>
#include <cstdlib>

CliOptions CliParser::parse(int argc, char* argv[]) {
    CliOptions options;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            options.showHelp = true;
            return options;
        }
        else if (arg == "--version" || arg == "-v") {
            options.showVersion = true;
            return options;
        }
        else if (arg == "--no-color") {
            options.noColor = true;
        }
        else if (arg == "--strings-only") {
            options.stringsOnly = true;
        }
        else if (arg == "--red-team" || arg == "-r") {
            options.redTeamMode = true;
        }
        else if (arg == "--disasm" || arg == "-d") {
            options.disasmMode = true;
            // Check if next arg is a number (instruction count)
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                char* endptr;
                long count = std::strtol(argv[i + 1], &endptr, 10);
                if (*endptr == '\0' && count > 0) {
                    options.disasmCount = static_cast<size_t>(count);
                    i++;
                }
            }
        }
        else if (arg == "--offset" || arg == "-o") {
            if (i + 1 < argc) {
                options.offset = std::strtoul(argv[++i], nullptr, 0);
            } else {
                std::cerr << "Error: --offset requires a value\n";
                options.showHelp = true;
                return options;
            }
        }
        else if (arg == "--length" || arg == "-l") {
            if (i + 1 < argc) {
                options.length = std::strtoul(argv[++i], nullptr, 0);
            } else {
                std::cerr << "Error: --length requires a value\n";
                options.showHelp = true;
                return options;
            }
        }
        else if (arg == "--min-string" || arg == "-m") {
            if (i + 1 < argc) {
                options.minStringLength = std::strtoul(argv[++i], nullptr, 10);
            } else {
                std::cerr << "Error: --min-string requires a value\n";
                options.showHelp = true;
                return options;
            }
        }
        else if (arg[0] == '-') {
            std::cerr << "Error: Unknown option '" << arg << "'\n";
            options.showHelp = true;
            return options;
        }
        else {
            options.filename = arg;
        }
    }
    
    if (options.filename.empty() && !options.showHelp && !options.showVersion) {
        options.showHelp = true;
    }
    
    return options;
}

void CliParser::printHelp(const char* programName) {
    std::cout << "\n\033[1mUSAGE:\033[0m\n";
    std::cout << "  " << programName << " [OPTIONS] <binary_file>\n\n";
    
    std::cout << "\033[1mOPTIONS:\033[0m\n";
    std::cout << "  \033[96m-h, --help\033[0m              Show this help message\n";
    std::cout << "  \033[96m-v, --version\033[0m           Show version information\n";
    std::cout << "  \033[96m-o, --offset <num>\033[0m      Start hex dump at offset (default: 0)\n";
    std::cout << "  \033[96m-l, --length <num>\033[0m      Number of bytes to display (default: 256)\n";
    std::cout << "  \033[96m-m, --min-string <num>\033[0m  Minimum string length (default: 5)\n";
    std::cout << "  \033[96m-d, --disasm [count]\033[0m    Disassemble instructions (default: 50)\n";
    std::cout << "  \033[96m--no-color\033[0m              Disable colored output\n";
    std::cout << "  \033[96m--strings-only\033[0m          Only extract and display strings\n";
    std::cout << "  \033[96m-r, --red-team\033[0m          Enable Red Team analysis mode\n";
    
    std::cout << "\n\033[1mEXAMPLES:\033[0m\n";
    std::cout << "  " << programName << " /bin/ls\n";
    std::cout << "  " << programName << " --disasm /bin/ls\n";
    std::cout << "  " << programName << " --disasm 100 --offset 0x1000 malware.exe\n";
    std::cout << "  " << programName << " --offset 0x1000 --length 512 malware.exe\n";
    std::cout << "  " << programName << " --strings-only --min-string 10 binary.dll\n";
    std::cout << "  " << programName << " --red-team suspicious.exe\n";
    std::cout << "  " << programName << " --no-color sample.bin > output.txt\n\n";
}

void CliParser::printVersion() {
    std::cout << "\n\033[1;96mBinAnalyzer\033[0m version \033[1;93m1.0\033[0m\n";
    std::cout << "Modern Binary Analysis Tool\n";
    std::cout << "Copyright (c) 2025 Oblivionsage\n";
    std::cout << "License: MIT\n";
    std::cout << "GitHub: https://github.com/Oblivionsage/BinAnalyzer\n\n";
}
