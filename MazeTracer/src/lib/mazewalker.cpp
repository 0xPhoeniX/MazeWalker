#include "pin.H"
#include "cfg.h"
#include "ProcessTrace.h"
#include "PEImage.h"
#include "Logger.h"
#include <iostream>
#include <fstream>
#include "cJSON.h"


using std::cerr;
using std::endl;
using std::string;

using namespace MazeWalker;

KNOB<string> KnobConfigFile(KNOB_MODE_WRITEONCE,  "pintool",
    "cfg", "", "specify configuration file path");
KNOB<int> KnobDelay(KNOB_MODE_WRITEONCE,  "pintool",
    "delay", "300000", "specify time for termination delay in millisecs");

ProcessTrace *pTrace = NULL;

INT32 Usage()
{
    cerr << "MazeWalker - the tool for rapid malware analysis. " << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v) {
    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
   
    Logger::Write("Where %s\n", pExceptInfo->GetCodeAsString().c_str());

    Logger::Write(
        ">>>>>>>>>>> Exception <<<<<<<<<<<\n \
        %s \n \
        \tException code=0x%x address=0x%x tid=%d\n \
        \t\teax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x \
        eip=%08x esp=%08x ebp=%08x\n \
        ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n\n \
        \tCallstack:\n\t\tFramePtr ChildEBP RetAddr\n",
        PIN_ExceptionToString(pExceptInfo).c_str(),
        pExceptInfo->GetExceptCode(), 
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EIP), PIN_ThreadId(),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EAX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EBX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_ECX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EDX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_ESI),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EDI),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EIP), 
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_ESP), 
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EBP));

    // log callstack    
    ADDRINT eip = PIN_GetPhysicalContextReg(pPhysCtxt, REG_EIP);
    ADDRINT esp = PIN_GetPhysicalContextReg(pPhysCtxt, REG_ESP);
    ADDRINT ebp = PIN_GetPhysicalContextReg(pPhysCtxt, REG_EBP);
    ADDRINT childebp = 0;

    int count = 0;
    while(ebp != 0 && count < 20)
    {
        if(PIN_SafeCopy(&childebp, (ADDRINT *)(ebp), 4) != 4) 
            break;
        if(PIN_SafeCopy(&eip, (ADDRINT *)(ebp + 4), 4) != 4) 
            break;      

        Logger::Write("\t\t ebp = 0x%x childebp = 0x%x eip = 0x%x\n", ebp, childebp, eip);

        if(PIN_SafeCopy(&ebp, (ADDRINT *)ebp, 4) != 4) 
            break;

        count++;
    }

    return EHR_UNHANDLED ;
}

VOID ContextCallback(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{
    switch(reason)
    {
    case CONTEXT_CHANGE_REASON_EXCEPTION:
        ADDRINT eip = PIN_GetContextReg(from, REG_EIP);
        ADDRINT esp = PIN_GetContextReg(from, REG_ESP);
        ADDRINT ebp = PIN_GetContextReg(from, REG_EBP);
        ADDRINT childebp = 0;

        Logger::Write("Where %s\n", RTN_Name(RTN_FindByAddress(eip)).c_str());
        
        Logger::Write(
            "\tException code=0x%x address=0x%x tid=%d\n \
            \t\teax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x \
            eip=%08x esp=%08x ebp=%08x\n \
            \tCallstack:\n\t\tFramePtr ChildEBP RetAddr\n",
            info, eip, tid,
            PIN_GetContextReg(from, REG_EAX),
            PIN_GetContextReg(from, REG_EBX),
            PIN_GetContextReg(from, REG_ECX),
            PIN_GetContextReg(from, REG_EDX),
            PIN_GetContextReg(from, REG_ESI),
            PIN_GetContextReg(from, REG_EDI),
            eip, esp, ebp);

        int count = 0;
        while(ebp != 0 && count < 20)
        {
            if(PIN_SafeCopy(&childebp, (ADDRINT *)(ebp), 4) != 4) 
                break;
            if(PIN_SafeCopy(&eip, (ADDRINT *)(ebp + 4), 4) != 4) 
                break;      

            Logger::Write("\t\t ebp = 0x%x childebp = 0x%x eip = 0x%x\n", ebp, childebp, eip);

            if(PIN_SafeCopy(&ebp, (ADDRINT *)ebp, 4) != 4) 
                break;

            count++;
        }
        break;
    }
}

// Analysis routin for call invocation.
void AddCallee(ADDRINT ins_addr, ADDRINT exec_target, ADDRINT regBased, THREADID tid, VOID* v)
{
    ProcessTrace* pTrace;
    Thread* thread;
    MemoryArea* ma;

    if (v == NULL) {
        Logger::Write("[%s] pTrace is NULL!!!\n", __FUNCTION__);
        return;
    }

    pTrace = (ProcessTrace*)v;
    ma = pTrace->addMemoryArea(ins_addr);

    if (ma == NULL) {
        Logger::Write("[%s] Memory area is NULL!!!\n", __FUNCTION__);
        return;
    }

    thread = ma->getThread(tid);
    if (thread == NULL) {
        Logger::Write("[%s] No record for the thread : %d\n", __FUNCTION__, tid);
        return;
    }

    Call* cur_call = thread->getCall(exec_target);
    if (cur_call) {
        cur_call->addXref(ins_addr);
    }
    else {
        thread->addCall(new Call(exec_target, ins_addr, pTrace->ResolveAddress(exec_target)));
    }
}

VOID BasicBlockAnalyzer(ADDRINT bbl_start, ADDRINT bbl_size, ADDRINT inst_num, THREADID tid, VOID* v)
{
    BasicBlock* bbl = NULL;
    ProcessTrace* pTrace;
    MemoryArea* ma;
    Thread* thread;

    if (v == NULL) {
        Logger::Write("[%s] pTrace is NULL!!!\n", __FUNCTION__);
        return;
    }
    pTrace = (ProcessTrace*)v;

    ma = pTrace->addMemoryArea(bbl_start);
    if (ma == NULL) {
        Logger::Write("[%s] Memory area is NULL!!!\n", __FUNCTION__);
        return;
    }

    thread = ma->getThread(tid);
    if (thread == NULL) {
        thread = new Thread(bbl_start, tid);
        ma->addThread(thread);
    }

    bbl = thread->getBBL(bbl_start);
    if (bbl) {
        ++(*bbl);
    }
    else {
        thread->addBBL(new BasicBlock(bbl_start, bbl_size + bbl_start, inst_num));
    }
}

VOID Trace(TRACE trace, VOID *v)
{
    ADDRINT disp;
    UINT32 has_ret = 0;
    MemoryArea* ma;
    Image* img = NULL;
    ProcessTrace* pTrace = (ProcessTrace*)v;
    
    if (v == NULL) {
        Logger::Write("[%s] pTrace is NULL!!!\n", __FUNCTION__);
        return;
    }

    // For legit in memory modules or 64bit versions not visible to pin (wow64)
    ma = pTrace->addMemoryArea(TRACE_Address(trace));
    if (pTrace->isAddressInScope(TRACE_Address(trace))) {
        Logger::Write("[%s] Tracing address : 0x%x\n", __FUNCTION__, TRACE_Address(trace));

        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
            // as BBL has only one possible exit, we are interested in the last instruction
            INS ins = BBL_InsTail(bbl);

            BBL_InsertCall(bbl,
                            IPOINT_BEFORE,
                            (AFUNPTR)BasicBlockAnalyzer, 
                            IARG_ADDRINT, BBL_Address(bbl),
                            IARG_ADDRINT, BBL_Size(bbl),
                            IARG_ADDRINT, BBL_NumIns(bbl),
                            IARG_THREAD_ID,
                            IARG_PTR, v,
                            IARG_END);

            if (INS_IsControlFlow(ins))
            {
                if (INS_IsCall(ins))
                {
                    if (INS_OperandIsReg(ins, 0))
                    {
                        REG base = INS_OperandMemoryBaseReg(ins, 0);
                        if (base ==  REG_INVALID())
                        {
                            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddCallee, 
                                                IARG_INST_PTR, 
                                                IARG_REG_VALUE, INS_OperandReg(ins, 0), 
                                                IARG_ADDRINT, 1,
                                                IARG_THREAD_ID,
                                                IARG_PTR, v,
                                                IARG_END);
                        }
                    }
                    else if (INS_OperandIsMemory(ins, 0))
                    {
                        disp = INS_MemoryDisplacement(ins);
                        REG base = INS_OperandMemoryBaseReg(ins, 0);
                        if (base ==  REG_INVALID())
                        {
                            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddCallee, 
                                                IARG_INST_PTR, 
                                                IARG_BRANCH_TARGET_ADDR,
                                                IARG_ADDRINT, 0, 
                                                IARG_THREAD_ID,
                                                IARG_PTR, v,
                                                IARG_END);
                        }
                        else
                        {
                            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddCallee, 
                                                IARG_INST_PTR, 
                                                IARG_BRANCH_TARGET_ADDR,
                                                IARG_ADDRINT, 1, 
                                                IARG_THREAD_ID,
                                                IARG_PTR, v,
                                                IARG_END);
                        }
                    }
                    else if (INS_OperandIsBranchDisplacement(ins, 0))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddCallee, 
                                            IARG_INST_PTR, 
                                            IARG_BRANCH_TARGET_ADDR,
                                            IARG_ADDRINT, 0, 
                                            IARG_THREAD_ID,
                                            IARG_PTR, v,
                                            IARG_END);
                    }
                }
                else if (INS_Opcode(ins) == XED_ICLASS_JMP)
                {
                    if (INS_OperandIsMemory(ins, 0) || INS_OperandIsReg(ins, 0))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                            (AFUNPTR)AddCallee, 
                                            IARG_INST_PTR, 
                                            IARG_BRANCH_TARGET_ADDR,
                                            IARG_ADDRINT, 0,
                                            IARG_THREAD_ID,
                                            IARG_PTR, v,
                                            IARG_END);
                    }
                    else if (INS_OperandIsReg(ins, 0))
                    {
                        REG base = INS_OperandMemoryBaseReg(ins, 0);
                        if (base ==  REG_INVALID())
                        {
                            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddCallee, 
                                                IARG_INST_PTR, 
                                                IARG_REG_VALUE, INS_OperandReg(ins, 0), 
                                                IARG_ADDRINT, 1,
                                                IARG_THREAD_ID,
                                                IARG_PTR, v,
                                                IARG_END);
                        }
                    }
                }
            }
        }
        if (ma && ma->StatusAt(TRACE_Address(trace), TRACE_Size(trace)) == MemoryAreaStatus::Different) {
            Logger::Write("Memory changed at 0x%x!\n", TRACE_Address(trace));
            ma->saveState(TRACE_Address(trace));
        }
    }
}

void api_callback(ADDRINT ins_addr, CONTEXT *ctx, ADDRINT ret_addr, ADDRINT trg_addr, ADDRINT tid, VOID* hook, VOID* v)
{
    Logger::Write("[%s] - ins=0x%x, ret=0x%x\n", __FUNCTION__, ins_addr, ret_addr);
    ProcessTrace* pTrace = (ProcessTrace*)v;

    if (v && pTrace->isAddressInScope(ret_addr))
    {
        ADDRINT ebp = PIN_GetContextReg(ctx, REG_ESP);
        MemoryArea* ma = pTrace->addMemoryArea(ret_addr);
        if (ma == NULL) {
            Logger::Write("[%s] Memory Area is NULL!!!\n", __FUNCTION__);
            return;
        }
        Thread* thread = ma->getThread(tid);
        if (thread == NULL) {
            Logger::Write("[%s] Thread variable is NULL!!!\n", __FUNCTION__);
            return;
        }
        
        Call* api_call = thread->getCall(trg_addr);
        if (api_call) {
            ApiHook* hook_ptr = (ApiHook*)hook;
            if (hook_ptr && hook_ptr->pre_parser) {
                api_call->Analyze(hook_ptr, (long*)(ebp + 4));
            }
        }
    }
}

// Analyze every image that is being loaded into the process.
VOID ImageLoad(IMG img, VOID *v)
{
    Logger::Write("\t\t%s\n", __FUNCTION__);

    ProcessTrace* pTrace = (ProcessTrace*)v;
    if (v == NULL) {
        Logger::Write("[%s] pTrace is NULL!!!\n", __FUNCTION__);
        return;
    }

    pTrace->addImage_(&img);

    // On each loaded image, its routines will be hooked per supplied configuration
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            const ApiHook* hook = pTrace->getConfig().getHook(strrchr(IMG_Name(img).c_str(), '\\') + 1, RTN_Name(rtn).c_str());
            if (hook) {
                RTN_Open(rtn);
                
                if (hook->pre_parser) {
                    RTN_InsertCall(rtn, IPOINT_BEFORE, 
                                    (AFUNPTR)api_callback,
                                    IARG_INST_PTR,
                                    IARG_CONST_CONTEXT,
                                    IARG_RETURN_IP,
                                    IARG_ADDRINT, RTN_Address(rtn),
                                    IARG_THREAD_ID,
                                    IARG_PTR, hook,
                                    IARG_PTR, v,
                                    IARG_END);
                }
                        
                if (hook->post_parser) {
                    RTN_InsertCall(rtn, IPOINT_AFTER, 
                                    (AFUNPTR)api_callback,
                                    IARG_CONST_CONTEXT,
                                    IARG_RETURN_IP,
                                    IARG_ADDRINT, RTN_Address(rtn),
                                    IARG_THREAD_ID,
                                    IARG_PTR, hook,
                                    IARG_PTR, v,
                                    IARG_END);
                }
                
                RTN_Close(rtn);
            }
        }
    }
}

void save_maze_log(VOID* v)
{
    Logger::Write("[%s]\n", __FUNCTION__);
    ProcessTrace* pTrace = (ProcessTrace*)v;
    cJSON* root = cJSON_CreateObject();
    std::ofstream json_out;

    pTrace->Export(pTrace->getConfig().getOutputDir());
    pTrace->toJson(root);

    json_out.open(pTrace->getConfig().getTraceLogFilePath());
    json_out << cJSON_Print(root);
    json_out.close();
}

// Internal thread for inforcing timeout execution delay.
// It's needed to stop the execution if sample runs more 
// then planned.
/*VOID InternalTimerThread(void* args)
{
    for (int i = 100; i < KnobDelay.Value(); i += 100) {
        //if (PIN_IsProcessExiting())
            PIN_ExitThread(0);

        PIN_Sleep(100);
    }

    save_maze_log();
    // According to PIN manual it should be called from
    // analysis routine but I did not notice any strange 
    // behaviour when the api was called from here.
    PIN_Detach();
}*/

VOID Fini(INT32 code, VOID *v)
{
    Logger::Write("%s\n", __FUNCTION__);
    save_maze_log(v);
}

VOID OutOfMemoryCallback(size_t size, VOID* v) {
    Logger::Write("Out of memory.\n");
    save_maze_log(v);
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc,argv))
        return Usage();
    pTrace = new ProcessTrace(KnobConfigFile.Value().c_str());

    if (pTrace->Initialize()) {

        Logger::Write("Starting instrumentation\n");

        // Register ImageLoad to be called when an image is loaded
        IMG_AddInstrumentFunction(ImageLoad, pTrace);

        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, pTrace);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, pTrace);

        PIN_AddContextChangeFunction(ContextCallback, 0);

        // Catch global internal exceptions
        PIN_AddInternalExceptionHandler(ExceptionHandler, 0);

        // Internal thread to terminate execution once delay timeout hit
        //PIN_SpawnInternalThread(InternalTimerThread, 0, 0, 0);

        // Monitor for out of memory issues
        PIN_AddOutOfMemoryFunction(OutOfMemoryCallback, pTrace);

        Logger::Write("Starting target program\n");
        // Start the program, never returns
        PIN_StartProgram();
    }

    LOG("[!!!] Please check configuration.\n");

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
