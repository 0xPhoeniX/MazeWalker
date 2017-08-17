#include "pin.H"
#include "mazewarker.h"
#include "pe.h"
#include "cfg.h"
#include <fstream>
#include <iostream>
#include <map>
#include <algorithm>
#include <list>
#include <string>
#include <iomanip>

#ifdef OS32
#include "python_support.h"
#include "api_log.h"
#endif

ADDRINT block_id = 0, thread_num = 1;
map<ADDRINT, BASIC_BLOCK_INFO> basic_blocks;
map<ADDRINT, BASIC_BLOCK_INFO> tid_basic_blocks[THREAD_LIMIT];
map<ADDRINT, CALL_INFO> calls;
map<ADDRINT, CALL_INFO> tid_calls[THREAD_LIMIT];
map<ADDRINT, TRACK_MEM_INFO> mem_info; 
map<ADDRINT, ADDRINT> tfuncs;
ADDRINT mem_reg_id = 0;
struct {ADDRINT base; ADDRINT limit;} stack_bases[THREAD_LIMIT];

KNOB<string> KnobConfigFile(KNOB_MODE_WRITEONCE,  "pintool",
    "cfg", "", "specify configuration file path");
KNOB<string> KnobOutputDir(KNOB_MODE_WRITEONCE,  "pintool",
    "out", "", "specify output directory path");

INT32 Usage()
{
    cerr << "MazeWalker - the tool for rapid malware analysis. " << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

VOID ImageLoad(IMG img, VOID *v)
{
    const std::string image_path = IMG_Name(img);
    ADDRINT image_base = IMG_StartAddress(img);

    LOG("[" + string(__FUNCTION__) + "]\n\tImage: " + image_path + 
        "\n\tStart Address: " + hexstr(image_base) +
        "\n\tID: " + decstr(IMG_Id(img)) + "\n");

    pe_watch_module((void*)image_base, image_path.c_str());
#ifdef OS32
    apply_api_filters(img);
#endif
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    save_maze_log();
#ifdef OS32
    unload_python();
#endif
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    W::MEMORY_BASIC_INFORMATION mbi;
    ADDRINT stack_ptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
    ADDRINT thread_func = PIN_GetContextReg(ctxt, REG_EAX);

    if (stack_ptr > 0x1000)
    {
        W::VirtualQuery((W::PVOID)stack_ptr, &mbi, sizeof(mbi));
        stack_bases[(int)threadid].limit = (ADDRINT)mbi.AllocationBase;
        stack_bases[(int)threadid].base = mbi.RegionSize + 
										  ((ADDRINT)mbi.BaseAddress - (ADDRINT)mbi.AllocationBase) + 
										  stack_bases[(int)threadid].limit;
    }

    if (thread_func > 0x1000)
    {
        ADDRINT base, size;

        if (DoTrace(thread_func) && get_address_info(thread_func, base, size, NULL))
        {
            map<ADDRINT, TRACK_MEM_INFO>::iterator iter;
            list<PCODE_BLOCK>::iterator diter;

            memory_monitor(thread_func, 32);
            tfuncs[threadid] = thread_func;

            iter = mem_info.find(base);
            if (iter != mem_info.end())
            {
                ADDRINT offset = thread_func - iter->second.base;
                for (diter = iter->second.code.begin(); diter != iter->second.code.end(); diter++)
                {
                    if (offset <= (*diter)->size && thread_func >= iter->second.base)
                    {
                        if (memcmp((void*)(base + offset), (*diter)->code + offset, 32) == 0)
                        {
                            (*diter)->tids->push_back(threadid);
                            break;
                        }
                    }
                }
            }

            thread_num++;
        }
    }
}

VOID InternalTimerThread(void *args)
{
    PIN_Sleep(1000);
    for (int i = 0; i < 300; i++)
    {
        if (PIN_IsProcessExiting())
            PIN_ExitThread(0);
        PIN_Sleep(1000);
    }
    PIN_Detach();
}

VOID DetachFunction(VOID *v)
{
    save_maze_log();
#ifdef OS32
    unload_python();
#endif
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc,argv))
        return Usage();

    if (load_cfg(KnobConfigFile.Value().c_str())) {
        cfg.output_dir = KnobOutputDir.Value();

#ifdef OS32
        load_python(cfg.script_path.c_str());
#endif
        pe_init_subsystem();

        // Register ImageLoad to be called when an image is loaded
        IMG_AddInstrumentFunction(ImageLoad, 0);

        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);

        PIN_AddContextChangeFunction(ContextCallback, 0);

        // Catch global internal exceptions
        PIN_AddInternalExceptionHandler(ExceptionHandler, 0);

        PIN_AddThreadStartFunction(ThreadStart, 0);

        PIN_SpawnInternalThread(InternalTimerThread, 0, 0, 0);
        PIN_AddDetachFunction(DetachFunction, 0);

        // Start the program, never returns
        PIN_StartProgram();
    }

    LOG("[!!!] Please check configuration.");

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
