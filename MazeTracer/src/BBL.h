#pragma once
#include "IReportObject.h"


namespace MazeWalker {

    // Representa a basic block of execution where it has one entrance
    // and one exit.

    class BasicBlock : public IReportObject {
    public:

        // ctor: s - start address, e - end address, 
        //       ins - number of instructions
        BasicBlock(int s, int e, int ins);

        int getStart() const { return _start; }
        
        int getID() const { return _id; }
        
        bool toJson(void* root ) const;

        // Increment the number of times the block was executed.
        BasicBlock& operator++() { _execs++; return *this; }

        ~BasicBlock() {}
    private:
        int _start, _ins_num, _id;
        int _execs, _end;
        static int _idGenerator;
    };
}