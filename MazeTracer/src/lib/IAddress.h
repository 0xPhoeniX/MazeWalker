#pragma once

namespace MazeWalker {

    // Abstract class to define an address. The implementation must
    // return the actual address with its enclosing memory area. 
    // The memory are must be defined by base and size.
    
    class IAddress {
    public:
        virtual int Address() const = 0;
        virtual int Base() const = 0;
        virtual int Size() const = 0;
    };
}