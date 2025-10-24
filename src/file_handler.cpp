#include "file_handler.hpp"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>

FileHandler::FileHandler(const std::string& filename)
    : filename_(filename), fileSize_(0), isOpen_(false), fd_(-1) {
}

FileHandler::~FileHandler() {
    close();
}

bool FileHandler::open() {
    fd_ = ::open(filename_.c_str(), O_RDONLY);
    if (fd_ < 0) {
        return false;
    }

    struct stat st;
    if (fstat(fd_, &st) < 0) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    fileSize_ = st.st_size;
    isOpen_ = true;
    return true;
}

void FileHandler::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    isOpen_ = false;
}

bool FileHandler::isOpen() const {
    return isOpen_;
}

size_t FileHandler::getSize() const {
    return fileSize_;
}

std::string FileHandler::getFilename() const {
    return filename_;
}

std::vector<uint8_t> FileHandler::readBytes(size_t offset, size_t count) {
    if (!isOpen_) {
        throw std::runtime_error("File is not open");
    }

    if (offset >= fileSize_) {
        return std::vector<uint8_t>();
    }

    size_t bytesToRead = std::min(count, fileSize_ - offset);
    std::vector<uint8_t> buffer(bytesToRead);

    if (lseek(fd_, offset, SEEK_SET) < 0) {
        throw std::runtime_error("Failed to seek in file");
    }

    ssize_t bytesRead = read(fd_, buffer.data(), bytesToRead);
    if (bytesRead < 0) {
        throw std::runtime_error("Failed to read from file");
    }

    buffer.resize(bytesRead);
    return buffer;
}

std::vector<uint8_t> FileHandler::readAll() {
    return readBytes(0, fileSize_);
}

// TODO: Add better error messages
// TODO: Implement retry logic for large files
