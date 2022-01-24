#pragma once
#include "MemoryArea.h"


namespace MazeWalker {

    // Implements an arbitrary memory area.
    // It is registered in MemoryTracer
    class Blob : public MemoryArea {
    public:
        Blob(int entry);

        static bool isValid(const char* data, size_t size);

    private:
        virtual const char* getFileType() const;
        virtual void processBeforeDump(char* data, size_t size);
    };
}