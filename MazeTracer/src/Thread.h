#pragma once
#include "IReportObject.h"
#include "BBL.h"
#include "Call.h"


namespace MazeWalker {
    class Thread : public IReportObject {
    public:
        Thread(int entry, int id);
        ~Thread();

        int ID() const { return _id; }

        // Store the bll object that the tread will execute
        void addBBL(BasicBlock* bbl);

        // Return bbl object by its start address, if preset
        BasicBlock* getBBL(int start) const;

        // Store call object that the thread will execute
        void addCall(Call* call);

        // Return call object by its target, if present
        Call* getCall(int target) const;

        // Store the class info into json dataset
        virtual bool toJson( Json::Value& root ) const;
    private:
        void* _calls;
        void* _call_lut;
        void* _bbls;
        void* _bbl_lut;
        int _entry;
        int _id;
    };
}