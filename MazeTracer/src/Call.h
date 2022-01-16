#pragma once
#include "IReportObject.h"
#include "cfg.h"

namespace MazeWalker {

    class Call : public IReportObject {
    public:
        // Create call object instance
        // @param target Address of the target call invocation
        // @param xref Address of the reference to the call
        Call(int target, int xref, const char* symbol);
        ~Call();

        // Add reference to the call
        //
        // @param xref: Address of the reference to the call
        void addXref(int xref);

        // Store analysis information of the current call. 
        // Example: the analysis can include the runtime
        // information of the call parameters. The results
        // will later be saved into the output trace file.
        void Analyze(ApiHook *hook, long* params);

        // Return the target address of the call.
        int getTarget() const { return _target; }

        // Return symbol of the target call, if present.
        const char* Symbol() const { return _name; }

        // Return the image name the target belongs to.
        const char* Image() const { return _image; }

        // Store the class info into json dataset
        virtual bool toJson( void* root ) const;

    private:
        void* _xrefs;
        int _target;
        int _execs;
        const char* _name;
        const char* _image;
        void* _params;
        void* _order;
    };
}