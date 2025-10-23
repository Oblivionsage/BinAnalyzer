cmake_minimum_required(VERSION 3.15)
project(BinAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)

# Find Capstone library and headers
find_library(CAPSTONE_LIBRARY 
    NAMES capstone
    PATHS /usr/lib /usr/local/lib /opt/homebrew/lib
    REQUIRED
)

find_path(CAPSTONE_INCLUDE_DIR 
    NAMES capstone/capstone.h
    PATHS /usr/include /usr/local/include /opt/homebrew/include
    REQUIRED
)

message(STATUS "Capstone library: ${CAPSTONE_LIBRARY}")
message(STATUS "Capstone include: ${CAPSTONE_INCLUDE_DIR}")

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CAPSTONE_INCLUDE_DIR}
)

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
