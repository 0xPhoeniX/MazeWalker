#include "WinAddress.h"
#include <windows.h>
#include <list>


namespace MazeWalker {

    WinAddress::WinAddress(int address, bool noCache) {
        _base = 0;
        _addr = address;
        _size = 0;

        if (noCache) {
            Resolve(this);
        }
        else {
            getFromCache(this);
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

    WinAddress::WinAddress(int addr, int base, int size) : _addr (addr), _base(base), _size(size) {}

    bool WinAddress::Resolve(WinAddress* obj) {
        MEMORY_BASIC_INFORMATION curr_info;
        int base = 0, size = 0, currAddr = 0;

        if (VirtualQuery((PVOID)(obj->_addr), &curr_info, sizeof(curr_info))) {
            currAddr = base = (int)curr_info.AllocationBase;
            while(VirtualQuery((PVOID)currAddr, &curr_info, sizeof(curr_info)) && 
                 (int)curr_info.AllocationBase == base) {
                     size += curr_info.RegionSize;
                     currAddr = (int)curr_info.BaseAddress + curr_info.RegionSize;
            }

            obj->_base = base;
            obj->_size = size;
            return true;
        }
        return false;
    }

    void WinAddress::getFromCache(WinAddress* obj) {
        static std::list<WinAddress> _cache;

        // Check if the given address was already resolved
        for (std::list<WinAddress>::iterator it = _cache.begin(); it != _cache.end(); ++it) {
            if (obj->_addr > it->Base() && obj->_addr < (it->Base() + it->Size())) {
                obj->_base = it->Base();
                obj->_size = it->Size();
                return;
            }
        }

        if (Resolve(obj)) {
            _cache.push_back(WinAddress(obj->Base(), obj->Base(), obj->Size()));
        }
    }
}