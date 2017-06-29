#include "pin.H"
#include "api_log.h"
#include <string>
#include <map>
#include "mazewarker.h"
#include "pe.h"
#include "cfg.h"

std::list<API_LOG> tid_api_params_log[THREAD_LIMIT];
extern ADDRINT rope_id[THREAD_LIMIT];

#include "python_support.h"

void api_analyzer_callback(CONTEXT *ctx, THREADID tid, ADDRINT ret_addr, ADDRINT cfg_index, ADDRINT addr, ADDRINT is_pre)
{
	PIN_LockClient();
	if (DoTrace(ret_addr))
	{
		char* result, *err, *analysis_fname;
		const char *parser;
		API_LOG api_log;
		ADDRINT ebp = PIN_GetContextReg(ctx, REG_ESP);

		if (is_pre) {
			analysis_fname = "pre_analyzer";
			parser = cfg.api_to_log[cfg_index].pre_parser.c_str();
		}
		else {
			analysis_fname = "post_analyzer";
			parser = cfg.api_to_log[cfg_index].post_parser.c_str();
		}

		result = call_analyzer(parser,
							   analysis_fname,
							   cfg.api_to_log[cfg_index].vars_num, 
							   (long*)(ebp + 4), &err);
			
		if (result) {
			api_log.params = std::string(result);
			api_log.params.erase(api_log.params.begin());
			api_log.params.erase(api_log.params.end() - 1);
			api_log.ret_addr = ret_addr;
			api_log.tid = tid;
			api_log.name = cfg.api_to_log[cfg_index].name;
			api_log.addr = addr;
			api_log.id = rope_id[tid] - 1;
			tid_api_params_log[tid].push_back(api_log);
		}
		else
			if (err)
				LOG("Error:" + string(err) + "\n");
	}
	PIN_UnlockClient();
}

void apply_api_filters(IMG img)
{
	for (int i = 0; i < cfg.api_to_log.capacity(); i++) {
		RTN api_obj = RTN_FindByName(img, cfg.api_to_log[i].name.c_str());
		if (RTN_Valid(api_obj)) {
            
			if (RTN_Valid(api_obj))
			{
				RTN_Open(api_obj);
				
				if (cfg.api_to_log[i].pre_parser.length() > 0)
					RTN_InsertCall(api_obj, IPOINT_BEFORE, (AFUNPTR)api_analyzer_callback,
									IARG_CONST_CONTEXT,
									IARG_THREAD_ID,
									IARG_RETURN_IP,
									IARG_ADDRINT,
									i,
									IARG_ADDRINT,
									RTN_Address(api_obj),
									IARG_ADDRINT,
									1,
									IARG_END);
						
				if (cfg.api_to_log[i].post_parser.length() > 0)
					RTN_InsertCall(api_obj, IPOINT_AFTER, (AFUNPTR)api_analyzer_callback,
									IARG_CONST_CONTEXT,
									IARG_THREAD_ID,
									IARG_RETURN_IP,
									IARG_ADDRINT,
									i,
									IARG_ADDRINT,
									RTN_Address(api_obj),
									IARG_ADDRINT,
									0,
									IARG_END);
                
				RTN_Close(api_obj);
			}
		}
	}
}