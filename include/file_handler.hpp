#ifndef FILE_HANDLER_HPP
#define FILE_HANDLER_HPP

#include <string>
#include <vector>
#include <cstdint>

class FileHandler {
public:
    FileHandler(const std::string& filename);
    ~FileHandler();

    bool open();
    void close();
    bool isOpen() const;
    
    size_t getSize() const;
    std::string getFilename() const;
    
    std::vector<uint8_t> readBytes(size_t offset, size_t count);
    std::vector<uint8_t> readAll();

private:
    std::string filename_;
    size_t fileSize_;
    bool isOpen_;
    int fd_;
};

#endif // FILE_HANDLER_HPP
