#include "pin.H"
#include "pe.h"
#include "mazewarker.h"
#include <algorithm>

ADDRINT rope_id[THREAD_LIMIT] = {0};

void AddCallee(ADDRINT ins_addr, ADDRINT exec_target, ADDRINT regBased, ADDRINT id, THREADID tid)
{
    ADDRINT data = 0;
    IMG img;
    ADDRINT key;

    key = exec_target;
    PIN_LockClient();
    img = IMG_FindByAddress(key);
    PIN_UnlockClient();

    if (tid_calls[tid].find(key) == tid_calls[tid].end())
    {
        tid_calls[tid][key].execs = 1;
        tid_calls[tid][key].callees[ins_addr].ids.push_back(rope_id[tid]);
        tid_calls[tid][key].isRegBased = (short)regBased;
        tid_calls[tid][key].bbl_id.push_back(id);
        tid_calls[tid][key].name = NULL;
		tid_calls[tid][key].isSuspect = 1;

        if (IMG_Valid(img))
        {
            UINT32 img_id = IMG_Id(img);
            tid_calls[tid][key].base = IMG_StartAddress(IMG_FindImgById(img_id));
            tid_calls[tid][key].name = pe_find_exported_api_name((void*)(tid_calls[tid][key].base), (void*)exec_target);
            if (tid_calls[tid][key].name == NULL)
            {
                LOG("Unable to find api name - base " + hexstr(tid_calls[tid][key].base) + " " + hexstr(exec_target) + "\n");
            }
        }
        else
        {
            W::MEMORY_BASIC_INFORMATION curr_info;

            tid_calls[tid][key].base = 0;
            if (W::VirtualQuery((W::PVOID)key, &curr_info, sizeof(curr_info)))
                tid_calls[tid][key].base = (ADDRINT)curr_info.AllocationBase;
        }
    }
    else
    {
        tid_calls[tid][key].execs++;
        tid_calls[tid][key].callees[ins_addr].ids.push_back(rope_id[tid]);
    }

    rope_id[tid]++;
}

VOID PIN_FAST_ANALYSIS_CALL BasicBlockAnalyzer(ADDRINT bbl_start, ADDRINT bbl_size, ADDRINT inst_num, ADDRINT id, THREADID tid)
{
    if (tid_basic_blocks[tid].find(bbl_start) == tid_basic_blocks[tid].end())
    {
        map<ADDRINT, TRACK_MEM_INFO>::iterator iter;
        list<PCODE_BLOCK>::iterator diter;
        ADDRINT base, size;

        tid_basic_blocks[tid][bbl_start].bbl_start = bbl_start;
        tid_basic_blocks[tid][bbl_start].ins_num = inst_num;
        tid_basic_blocks[tid][bbl_start].executions = 1;
        tid_basic_blocks[tid][bbl_start].id = id;
        tid_basic_blocks[tid][bbl_start].bbl_end = bbl_start + bbl_size;

        if (get_address_info(bbl_start, base, size, NULL))
        {
            iter = mem_info.find(base);
            if (iter != mem_info.end())
            {
                ADDRINT offset = bbl_start - iter->second.base;
                for (diter = iter->second.code.begin(); diter != iter->second.code.end(); diter++)
                {
                    if (offset <= (*diter)->size && bbl_start >= iter->second.base)
                    {
                        if (memcmp((void*)(base + offset), (*diter)->code + offset, bbl_size) == 0)
                        {
                            std::list<ADDRINT>::iterator findIter = find((*diter)->tids->begin(), (*diter)->tids->end(), tid);
                            if (findIter == end(*((*diter)->tids)))
                            {
                                (*diter)->tids->push_back(tid);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    else 
    {
        tid_basic_blocks[tid][bbl_start].executions++;
    }
}

VOID Trace(TRACE trace, VOID *v)
{
    ADDRINT disp;
    UINT32 has_ret = 0;

    if (DoTrace(TRACE_Address(trace)))
    {
        LOG("["+ hexstr(TRACE_Address(trace)) + "]\n");

        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
			// as BBL has only one possible exit, we are interested in the last instruction
            INS ins = BBL_InsTail(bbl);

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
                                                IARG_UINT32, block_id,
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
                                                IARG_UINT32, block_id,
                                                IARG_THREAD_ID,
                                                IARG_END);
                        }
                        else
                        {
                            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AddCallee, 
                                                IARG_INST_PTR, 
                                                IARG_BRANCH_TARGET_ADDR,
                                                IARG_ADDRINT, 1, 
                                                IARG_UINT32, block_id,
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
                                            IARG_UINT32, block_id,
                                            IARG_THREAD_ID,
                                            IARG_END);
                    }
                }
                else if (INS_Opcode(ins) == XED_ICLASS_JMP)
                {
                    if (INS_OperandIsMemory(ins, 0))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                            (AFUNPTR)AddCallee, 
                                            IARG_INST_PTR, 
                                            IARG_BRANCH_TARGET_ADDR,
                                            IARG_ADDRINT, 0,
                                            IARG_UINT32, block_id,
                                            IARG_THREAD_ID,
                                            IARG_END);
                    }
                }
            }

            BBL_InsertCall(bbl,
                            IPOINT_BEFORE,
                            (AFUNPTR)BasicBlockAnalyzer,
                            IARG_FAST_ANALYSIS_CALL, 
                            IARG_ADDRINT, BBL_Address(bbl),
                            IARG_ADDRINT, BBL_Size(bbl),
                            IARG_ADDRINT, BBL_NumIns(bbl),
                            IARG_ADDRINT, block_id,
                            IARG_THREAD_ID,
                            IARG_END);
            block_id++;
        }
        memory_monitor(TRACE_Address(trace), TRACE_Size(trace));
    }
}
