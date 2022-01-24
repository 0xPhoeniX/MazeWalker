#pragma once
#include "IAddress.h"

namespace MazeWalker {

    // Windows implementation of the address definition.

    class WinAddress : public IAddress {
    public:
        WinAddress(int address);
        WinAddress(const WinAddress& other);
        WinAddress& operator=(const WinAddress& other);

        virtual int Address() const;
        virtual int Base() const;
        virtual int Size() const;

        virtual ~WinAddress() {}
    private:
        int _addr, _base, _size;
    };
}