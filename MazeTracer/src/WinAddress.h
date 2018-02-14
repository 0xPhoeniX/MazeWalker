#pragma once
#include "IAddress.h"

namespace MazeWalker {

    // Windows implementation of the address definition.

    class WinAddress : public IAddress {
    public:
        WinAddress(int address, bool noCache = false);
        WinAddress(const WinAddress& other);
        WinAddress& operator=(const WinAddress& other);

        virtual int Address() const;
        virtual int Base() const;
        virtual int Size() const;

        virtual ~WinAddress() {}
    private:
        WinAddress(int addr, int base, int size);
        int _addr, _base, _size;

        // Internal cache of already resolved addresses 
        // for performance optimization.
        static void getFromCache(WinAddress* obj);
        static bool Resolve(WinAddress* obj);
    };
}