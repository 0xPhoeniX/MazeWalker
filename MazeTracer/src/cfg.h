#pragma once

namespace MazeWalker {
    
    class ApiHook {
    public:
        // ctor. 
        // @param l Library name.
        // @param n API name.
        // @param pre Pre-API invocation analysis routine name.
        // @param post Post-API invocation analysis routine name.
        ApiHook(const char* l,
                const char* n,
                const char* pre,
                const char* post,
                int vars) : name(n), lib(l),
                            pre_parser(pre),
                            post_parser(post),
                            vars_num(vars) {}

        ~ApiHook() {}
        const char* name;
        const char* lib;
        const char* pre_parser;
        const char* post_parser;
        int vars_num;
    };

    // Configuration storage class.
    class CFG {
    public:
        CFG(const char* path);
        ~CFG() {}

        // As PIN does not support dynamic loading of the libraries, 
        // this trick is used to load whatever lib is needed before the 
        // instrumentation starts.
        bool PreloadLibraries() const;

        // Check if the hash is white listed by the configuration. 
        // Currently imphash and exphash are supported.
        bool isHashWhitelisted(const char* hash) const;

        // Check if the path is white listed by the configuration.
        // It is used to filter out OS libraries from instrumentation.
        bool isPathWhitelisted(const char* path) const;

        // Check if the module is white listed in the configuration.
        // It is used to filter out OS libraries from instrumentation.
        bool isModuleWhitelisted(const char* name) const;
        const char* getScriptsDir() const;
        const char* getRootDir() const;
        const char* getOutputDir() const;
        const char* getLogFilePath() const;
        const char* getTraceLogFilePath() const;

        // Returns a description of API analysis configuration.
        const ApiHook* getHook(const char* lib, const char* api) const;

    private:
        CFG(const CFG &) { }
        CFG &operator=(const CFG &) { return *this; }

        void* _cfg_data;
        void* _hook_data;
        const char* log_file_path;
        const char* trace_log;
        const char* out_dir_path;
        char* root_dir;
        char* scripts_dir;
    };
}
