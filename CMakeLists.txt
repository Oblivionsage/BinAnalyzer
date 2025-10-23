cmake_minimum_required(VERSION 3.15)
project(BinAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)

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
)

target_link_libraries(binanalyzer OpenSSL::Crypto)
