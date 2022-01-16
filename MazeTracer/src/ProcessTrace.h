#pragma once
#include "MemoryArea.h"
#include "IReportObject.h"
#include "Image.h"
#include "cfg.h"
//#include "MemoryTracer.h"


namespace MazeWalker {

    // Singleton class to manage tracing process.
    class ProcessTrace : IReportObject {
    public:
        ProcessTrace(const char* cfg_path);
        ~ProcessTrace();

        // Should this address be traced. It goes according to the 
        // configuration white-listing.
        bool isAddressInScope(int address) const;

        void addImage_(void* imgObj);
        const char* ResolveAddress(int address);
        MemoryArea* addMemoryArea(int address);

        // Export the whole tracing accumulated info into the json
        // file.
        //
        // dir: The directory to store the results.
        void Export(const char* dir) const;
        bool toJson(void* root) const;

        // Initialize the tracing process based on the configuration
        // file. If the configuration parsing succeeded, we are good to go.
        bool Initialize();
        const CFG& getConfig() const { return cfg; }

    private:
        ProcessTrace(const ProcessTrace& other);
        ProcessTrace& operator=(const ProcessTrace& other);

        void* _mas;
        void* modules;
        CFG cfg;
        bool python_ready;
    };
}