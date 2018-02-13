#pragma once
#include "IReportObject.h"


namespace MazeWalker {

    // Base class for enabling general analysis based on Python scripts.
    // It's responsible for initializing Python interpreter.
    class PythonBasedAnalysis : public IReportObject {
    public:
        // ctor.
        PythonBasedAnalysis();
        virtual ~PythonBasedAnalysis();
    protected:
        static bool ready;
        static int refs;
    };
}