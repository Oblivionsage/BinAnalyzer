cmake_minimum_required(VERSION 3.15)
project(BinAnalyzer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/file_handler.cpp
    src/hex_viewer.cpp
    src/hash_calculator.cpp
    src/pe_parser.cpp
    src/cli_parser.cpp
    src/import_analyzer.cpp
    src/security_analyzer.cpp
    src/advanced_analyzer.cpp
)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Executable
add_executable(binanalyzer ${SOURCES})

# Link OpenSSL for hash calculations
find_package(OpenSSL REQUIRED)
target_link_libraries(binanalyzer OpenSSL::SSL OpenSSL::Crypto)

# Install
install(TARGETS binanalyzer DESTINATION bin)
