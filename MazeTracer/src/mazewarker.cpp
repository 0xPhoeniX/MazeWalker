#include "pin.H"
#include "cfg.h"
#include <fstream>
#include <iostream>
#include <map>
#include <algorithm>
#include <list>
#include <string>
#include <iomanip>
#include "ProcessTrace.h"
#include "ContextAnalyzer.h"
#include "MemoryTracer.h"


using namespace MazeWalker;

KNOB<string> KnobConfigFile(KNOB_MODE_WRITEONCE,  "pintool",
    "cfg", "", "specify configuration file path");
KNOB<int> KnobDelay(KNOB_MODE_WRITEONCE,  "pintool",
    "delay", "300000", "specify time for termination delay in millisecs");

INT32 Usage()
{
    cerr << "MazeWalker - the tool for rapid malware analysis. " << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
	char buf[1024];

    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
	LOG("\n\n\n[" + string(__FUNCTION__) + "]\n >>>>>>>>>>> Exception <<<<<<<<<<<\n");
    LOG(PIN_ExceptionToString(pExceptInfo));
	
    memset(buf, 0, sizeof(buf));
    sprintf_s(buf, sizeof(buf) - 1, 
        "\tException code=0x%x address=0x%x tid=%d\n"
        "\t\teax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x "
        "eip=%08x esp=%08x ebp=%08x\n",
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
    LOG(string(buf));
	LOG("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n\n");

	// log callstack    
	ADDRINT eip = PIN_GetPhysicalContextReg(pPhysCtxt, REG_EIP);
    ADDRINT esp = PIN_GetPhysicalContextReg(pPhysCtxt, REG_ESP);
    ADDRINT ebp = PIN_GetPhysicalContextReg(pPhysCtxt, REG_EBP);
    ADDRINT childebp = 0;
    memset(buf, 0, sizeof(buf));
    sprintf_s(buf, sizeof(buf) - 1, 
        "\tCallstack:\n"
        "\t\tFramePtr ChildEBP RetAddr\n");
    LOG(buf);

    int count = 0;
    memset(buf, 0, sizeof(buf));
    while(ebp != 0 && count < 20)
    {
        if(PIN_SafeCopy(&childebp, (ADDRINT *)(ebp), 4) != 4) 
            break;
        if(PIN_SafeCopy(&eip, (ADDRINT *)(ebp + 4), 4) != 4) 
            break;      

        sprintf_s(buf, sizeof(buf) -1, "\t\t%08x %08x %08x\n", 
            ebp, childebp, eip);
        LOG(buf);

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
    
        char buf[1024];
        memset(buf, 0, sizeof(buf));
        sprintf_s(buf, sizeof(buf) - 1, 
            "\tException code=0x%x address=0x%x tid=%d\n"
            "\t\teax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x "
            "eip=%08x esp=%08x ebp=%08x\n",
            info, eip, tid,
            PIN_GetContextReg(from, REG_EAX),
            PIN_GetContextReg(from, REG_EBX),
            PIN_GetContextReg(from, REG_ECX),
            PIN_GetContextReg(from, REG_EDX),
            PIN_GetContextReg(from, REG_ESI),
            PIN_GetContextReg(from, REG_EDI),
            eip, esp, ebp);
        LOG("[" + string(__FUNCTION__) + "]\n" + string(buf));

        // log callstack        
        memset(buf, 0, sizeof(buf));
        sprintf_s(buf, sizeof(buf) - 1, 
            "\tCallstack:\n"
            "\t\tFramePtr ChildEBP RetAddr\n");
        LOG(buf);

        int count = 0;
        memset(buf, 0, sizeof(buf));
        while(ebp != 0 && count < 20)
        {
            if(PIN_SafeCopy(&childebp, (ADDRINT *)(ebp), 4) != 4) 
                break;
            if(PIN_SafeCopy(&eip, (ADDRINT *)(ebp + 4), 4) != 4) 
                break;      

            sprintf_s(buf, sizeof(buf) -1, "\t\t%08x %08x %08x\n", 
                ebp, childebp, eip);
            LOG(buf);

            if(PIN_SafeCopy(&ebp, (ADDRINT *)ebp, 4) != 4) 
                break;

            count++;
        }
        break;
    }
}

// Analysis routing for call invocation.
void AddCallee(ADDRINT ins_addr, ADDRINT exec_target, ADDRINT regBased, THREADID tid)
{
	Thread* thread = MemoryTracer::Instance().getMemoryArea(ins_addr)->getThread(tid);

	if (thread) {
		Call* cur_call = thread->getCall(exec_target);
		if (cur_call) {
			cur_call->addXref(ins_addr);
		}
		else {
			thread->addCall(new Call(exec_target, ins_addr));
		}
	}
	else {
		LOG(string(__FUNCTION__) + ": [!!!]No record for the thread: "+ decstr(tid) + "\n");
	}
}

VOID PIN_FAST_ANALYSIS_CALL BasicBlockAnalyzer(ADDRINT bbl_start, ADDRINT bbl_size, ADDRINT inst_num, THREADID tid)
{
	BasicBlock* bbl = NULL;
	MemoryArea* ma = MemoryTracer::Instance().getMemoryArea(bbl_start);
	Thread* thread = ma->getThread(tid);

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
	MemoryArea* ma = NULL;
	Image* img = NULL;

	// We need this check because of any custom loaded/decrypted (inmemory) libraries
	// as PIN will not detect them and we still do not need known libraries to be traced.
	if (ProcessTrace::Instance().isAddressInScope(TRACE_Address(trace))) {
		ma = MemoryTracer::Instance().getMemoryArea(TRACE_Address(trace));
		if (ma && (img = dynamic_cast<Image*>(ma))) {
			ProcessTrace::Instance().addImage(img);
		}

		if (ProcessTrace::Instance().isAddressInScope(TRACE_Address(trace)))
		{
			LOG(string(__FUNCTION__) + ": checking ["+ hexstr(TRACE_Address(trace)) + "]\n");

			for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
			{
				// as BBL has only one possible exit, we are interested in the last instruction
				INS ins = BBL_InsTail(bbl);

				BBL_InsertCall(bbl,
							   IPOINT_BEFORE,
							   (AFUNPTR)BasicBlockAnalyzer,
							   IARG_FAST_ANALYSIS_CALL, 
							   IARG_ADDRINT, BBL_Address(bbl),
							   IARG_ADDRINT, BBL_Size(bbl),
							   IARG_ADDRINT, BBL_NumIns(bbl),
							   IARG_THREAD_ID,
							   IARG_END);

				if (INS_IsBranchOrCall(ins))
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
													IARG_END);
							}
							else
							{
								INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddCallee, 
													IARG_INST_PTR, 
													IARG_BRANCH_TARGET_ADDR,
													IARG_ADDRINT, 1, 
													IARG_THREAD_ID,
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
													IARG_END);
							}
						}
					}
				}
			}
			if (ma) {
				ProcessTrace::Instance().addMemoryArea(ma);
				if (ma->StatusAt(TRACE_Address(trace), TRACE_Size(trace)) == MemoryAreaStatus::Different)
					ma->saveState(TRACE_Address(trace));
			}
		}
	}
}

void pre_api_callback(CONTEXT *ctx, ADDRINT ret_addr, ADDRINT trg_addr, ADDRINT tid)
{
	PIN_LockClient();
	if (ProcessTrace::Instance().isAddressInScope(ret_addr))
	{
		ADDRINT ebp = PIN_GetContextReg(ctx, REG_ESP);
		Thread* thread = MemoryTracer::Instance().getMemoryArea(ret_addr)->getThread(tid);
		
		Call* api_call = thread->getCall(trg_addr);
		if (api_call) {
			api_call->addAnalysis(new PreCallAnalysis(ebp, *api_call));
		}
	}
	PIN_UnlockClient();
}

void post_api_callback(CONTEXT *ctx, ADDRINT ret_addr, ADDRINT trg_addr, ADDRINT tid)
{
	PIN_LockClient();
	if (ProcessTrace::Instance().isAddressInScope(ret_addr))
	{
		ADDRINT ebp = PIN_GetContextReg(ctx, REG_ESP);
		Thread* thread = MemoryTracer::Instance().getMemoryArea(ret_addr)->getThread(tid);

		Call* api_call = thread->getCall(trg_addr);
		if (api_call) {
			api_call->addAnalysis(new PostCallAnalysis(ebp, *api_call));
		}
	}
	PIN_UnlockClient();
}

// Analyze every image that is being loaded into the process.
VOID ImageLoad(IMG img, VOID *v)
{
	Image* image = MemoryTracer::Instance().CreateImage(&img);
	ProcessTrace::Instance().addImage(image);
	
	if (IMG_IsMainExecutable(img))
		return;

	// On each loaded image, its routines will be hooked per supplied configuration
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
			const ApiHook* hook = CFG::Instance().getHook(strrchr(IMG_Name(img).c_str(), '\\') + 1, RTN_Name(rtn).c_str());
			if (hook) {
				RTN_Open(rtn);
				
				if (hook->pre_parser) {
					RTN_InsertCall(rtn, IPOINT_BEFORE, 
									(AFUNPTR)pre_api_callback,
									IARG_CONST_CONTEXT,
									IARG_RETURN_IP,
									IARG_ADDRINT,
									RTN_Address(rtn),
									IARG_THREAD_ID,
									IARG_END);
				}
						
				if (hook->post_parser) {
					RTN_InsertCall(rtn, IPOINT_AFTER, 
									(AFUNPTR)post_api_callback,
									IARG_CONST_CONTEXT,
									IARG_RETURN_IP,
									IARG_ADDRINT,
									RTN_Address(rtn),
									IARG_THREAD_ID,
									IARG_END);
				}
                
				RTN_Close(rtn);
			}
		}
	}
}

void save_maze_log()
{
	Json::StyledWriter writer;
	Json::Value root;
	std::ofstream json_out;
	std::ostringstream json_fname;

	ProcessTrace::Instance().Export(CFG::Instance().getOutputDir());
	ProcessTrace::Instance().toJson(root);

	if (!root.empty()) {
		json_fname << CFG::Instance().getOutputDir() << "\\maze_walk_" << PIN_GetPid() << ".json";
		json_out.open(json_fname.str());
		json_out << writer.write(root);
		json_out.close();
	}
}

// Internal thread for inforcing timeout execution delay.
// It's needed to stop the execution if sample runs more 
// then planned.
VOID InternalTimerThread(void *args)
{
	for (int i = 100; i < KnobDelay.Value(); i += 100) {
		if (PIN_IsProcessExiting())
			PIN_ExitThread(0);

		PIN_Sleep(100);
	}

	save_maze_log();
	// According to PIN manual it should be called from
	// analysis routine but I did not notice any strange 
	// behaviour when the api was called from here.
	PIN_Detach();
}

VOID Fini(INT32 code, VOID *v)
{
    save_maze_log();
}

VOID OutOfMemoryCallback(size_t size, VOID* v) {
	LOG(string(__FUNCTION__) + ": Out of memory.\n");
	save_maze_log();
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc,argv))
        return Usage();

	if (ProcessTrace::Instance().Initialize(KnobConfigFile.Value().c_str())) {

        // Register ImageLoad to be called when an image is loaded
        IMG_AddInstrumentFunction(ImageLoad, 0);

        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);

        PIN_AddContextChangeFunction(ContextCallback, 0);

        // Catch global internal exceptions
        PIN_AddInternalExceptionHandler(ExceptionHandler, 0);

		// Internal thread to terminate execution once delay timeout hit
        PIN_SpawnInternalThread(InternalTimerThread, 0, 0, 0);

		// Monitor for out of memory issues
		PIN_AddOutOfMemoryFunction(OutOfMemoryCallback, 0);

        // Start the program, never returns
        PIN_StartProgram();
    }

    LOG("[!!!] Please check configuration.");

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
