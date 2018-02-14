#pragma once
#include "Image.h"


namespace MazeWalker {

    // The class implements a memory area that rapresents in-memory PE Image.
    // It is registered in MemoryTracer.
    class PEImage : public Image {
    public:
        PEImage(int entry, int base, size_t size, const char* path = NULL);
        virtual const char* Resolve(int address) const;
        virtual const char* Name() const;
        virtual const char* Path() const;
        virtual const char* ImpHash() const;
        virtual const char* ExpHash() const;

        static bool isValid(const char* data, size_t size);
        virtual ~PEImage();

    private:
        virtual void processBeforeDump(char* data, size_t size);
        virtual const char* getFileType() const;

        char* _imphash;
        char* _exphash;
        char* _path;
        char* _name;
    };
}