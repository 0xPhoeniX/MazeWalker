#include "Blob.h"


namespace MazeWalker {

    Blob::Blob(int entry) : MemoryArea(entry) {
    }

    const char* Blob::getFileType() const {
        return "mem";
    }

    bool Blob::isValid(const char* data, size_t size) {
        return true;
    }

    void Blob::processBeforeDump(char* data, size_t size) {
        return;
    }
}