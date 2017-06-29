#ifndef _MAZEWARKER_H_
#define _MAZEWARKER_H_

#include <list>
#include <map>
#include <string>
#include "pin.H"

namespace W {
    #include <windows.h>
}

#define THREAD_LIMIT 1000
#define MAZEWALKER_DEBUG 1

typedef struct _ExecBasicBlock
{
	ADDRINT bbl_start, bbl_end;
	ADDRINT ins_num;
	ADDRINT executions;
	map<ADDRINT, ADDRINT> tids;
	ADDRINT id;
	UINT32  has_ret;
} BASIC_BLOCK_INFO;

typedef struct _CALL_ITEM
{
	ADDRINT count;
	list<ADDRINT> ids;
} CALL_ITEM;

typedef struct _CALL_INFO
{
	ADDRINT execs;
	ADDRINT base;
	short isRegBased;
	list<ADDRINT> rets;
	list<ADDRINT> bbl_id;
	map<ADDRINT, CALL_ITEM> callees;
	char *name;
} CALL_INFO, *PCALL_INFO;

typedef struct _CODE_BLOCK
{
	char* code;
	ADDRINT size;
	ADDRINT entry;
	int protection;
	int type;
	int hash;
	list<ADDRINT> *bbls;
	list<ADDRINT> *tids;
	ADDRINT id;
} CODE_BLOCK, *PCODE_BLOCK;

typedef struct _MEM_BLOCK
{
	ADDRINT base;
	ADDRINT pid;
	std::list<PCODE_BLOCK> code;
	ADDRINT id;
} TRACK_MEM_INFO;

typedef struct _API_LOG
{
	ADDRINT ret_addr, addr, id;
	ADDRINT tid;
	std::string name;
	std::string params;
} API_LOG, *PAPI_LOG;

extern ADDRINT block_id;
extern map<ADDRINT, BASIC_BLOCK_INFO> basic_blocks;
extern map<ADDRINT, CALL_INFO> calls;
extern map<ADDRINT, CALL_INFO> tid_calls[THREAD_LIMIT];
extern map<ADDRINT, BASIC_BLOCK_INFO> tid_basic_blocks[THREAD_LIMIT];
extern list<API_LOG> tid_api_params_log[THREAD_LIMIT];
extern map<ADDRINT, TRACK_MEM_INFO> mem_info;
extern map<ADDRINT, ADDRINT> tfuncs;
extern ADDRINT mem_reg_id;
extern PIN_LOCK lock;

bool get_address_info(ADDRINT addr, ADDRINT& base, ADDRINT& size, W::MEMORY_BASIC_INFORMATION *info);
bool DoTrace(ADDRINT address);
bool memory_monitor(ADDRINT addr, ADDRINT tsize);

void apply_api_filters(IMG img);
void log(string msg);
void save_maze_log();

VOID ContextCallback(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v);
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v);
VOID Trace(TRACE trace, VOID *v);

#endif