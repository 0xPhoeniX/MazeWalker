#include "WinAddress.h"
#include <windows.h>
#include <list>
#include "Logger.h"


namespace MazeWalker {

    WinAddress::WinAddress(int address) {
        MEMORY_BASIC_INFORMATION curr_info;
        _base = 0;
        _addr = address;
        _size = 0;

        int currAddr = 0;

        if (VirtualQuery((PVOID)(address), &curr_info, sizeof(curr_info))) {
            _base = (int)curr_info.AllocationBase;
            _size = curr_info.RegionSize;
        }
    }

    WinAddress::WinAddress(const WinAddress& other) {
        _base = other._base;
        _addr = other._addr;
        _size = other._size;
    }

    WinAddress& WinAddress::operator=(const WinAddress& other) {
        _size = other._size;
        _addr = other._addr;
        _base = other._base;

        return *this;
    }

    int WinAddress::Address() const { return _addr; }
    int WinAddress::Base() const { return _base; }
    int WinAddress::Size() const { return _size; }
}