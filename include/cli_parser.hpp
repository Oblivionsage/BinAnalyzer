#ifndef CLI_PARSER_HPP
#define CLI_PARSER_HPP
#include <string>
#include <vector>
struct CliOptions {
    std::string filename;
    size_t offset = 0;
    size_t length = 256;
    bool noColor = false;
    bool stringsOnly = false;
    bool showHelp = false;
    bool showVersion = false;
    bool redTeamMode = false;
    bool disasmMode = false;
    size_t minStringLength = 5;
    size_t disasmCount = 50;
    std::string architecture = "auto";  // x86, x64, arm, arm64, thumb, auto
};
class CliParser {
public:
    static CliOptions parse(int argc, char* argv[]);
    static void printHelp(const char* programName);
    static void printVersion();
};
#endif // CLI_PARSER_HPP
