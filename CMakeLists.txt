cmake_minimum_required(VERSION 3.15)
project(BinAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)

# Find Capstone
find_library(CAPSTONE_LIBRARY capstone REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Source files
add_executable(binanalyzer
    src/main.cpp
    src/file_handler.cpp
    src/hex_viewer.cpp
    src/hash_calculator.cpp
    src/pe_parser.cpp
    src/cli_parser.cpp
    src/import_analyzer.cpp
    src/security_analyzer.cpp
    src/packer_detector.cpp
    src/shellcode_detector.cpp
    src/ioc_extractor.cpp
    src/string_analyzer.cpp
    src/advanced_analyzer.cpp
    src/disassembler.cpp
)

# Link libraries
target_link_libraries(binanalyzer 
    OpenSSL::Crypto
    ${CAPSTONE_LIBRARY}
)
