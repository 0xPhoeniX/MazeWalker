#include "Blob.h"


namespace MazeWalker {

    //REGISTER_DEFAULTMATYPE(Blob);

    Blob::Blob(int entry, int base, size_t size) : MemoryArea(entry, base, size) {
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