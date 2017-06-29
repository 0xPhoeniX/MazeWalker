#include "pin.H"
#include "mazewarker.h"
#include "parson.h"
#include <algorithm>
#include "cfg.h"

#ifdef OS32
#include "api_log.h"
#endif

extern ADDRINT thread_num;

void log(std::string msg)
{
	LOG(msg);
}

bool save_bbls(JSON_Object *root_object, map<ADDRINT, BASIC_BLOCK_INFO> &basic_blocks)
{
	map<ADDRINT, BASIC_BLOCK_INFO>::iterator iter;
	map<ADDRINT, ADDRINT>::iterator tid_iter;

	if (basic_blocks.begin() == basic_blocks.end())
		return false;

	JSON_Value *blocks_val = json_value_init_array();
	JSON_Array *blocks = json_value_get_array(blocks_val);

	for (iter = basic_blocks.begin(); iter != basic_blocks.end(); iter++)
	{
		JSON_Value *block_val = json_value_init_object();
		JSON_Object *block = json_value_get_object(block_val);

		JSON_Value *tids_val = json_value_init_array();
		JSON_Array *tids = json_value_get_array(tids_val);

		json_object_set_number(block, "id", iter->second.id);
		json_object_set_number(block, "start", iter->second.bbl_start);
		json_object_set_number(block, "end", iter->second.bbl_end);
		json_object_set_number(block, "inst", iter->second.ins_num);
		json_object_set_number(block, "reps", iter->second.executions);
		json_object_set_number(block, "ret", iter->second.has_ret);

		json_array_append_value(blocks, block_val);
	}

	json_object_set_value(root_object, "bbls", blocks_val);

	return true;
}

bool save_mas(JSON_Object *root_object)
{
	if (mem_info.begin() != mem_info.end()) {
		JSON_Value *mem_dumps_val = json_value_reserve_array(mem_reg_id);
		JSON_Array *mem_dumps = json_value_get_array(mem_dumps_val);
		
		map<ADDRINT, TRACK_MEM_INFO>::iterator iter;

		for (iter = mem_info.begin(); iter != mem_info.end(); iter++)
		{
			list<PCODE_BLOCK>::iterator dump_iter;
			JSON_Value *dump_files_val = json_value_init_array();
			JSON_Array *dump_files = json_value_get_array(dump_files_val);
			JSON_Value *dump_obj_val = json_value_init_object();
			JSON_Object *dump_obj = json_value_get_object(dump_obj_val);

			for (dump_iter = iter->second.code.begin(); dump_iter != iter->second.code.end(); dump_iter++)
			{
				list<ADDRINT>::iterator bbl_iter;
				JSON_Value *dump_file_val = json_value_init_object();
				JSON_Object *dump_file_obj = json_value_get_object(dump_file_val);

				JSON_Value *tids_val = json_value_init_array();
				JSON_Array *tids = json_value_get_array(tids_val);

				for (bbl_iter = (*dump_iter)->tids->begin(); bbl_iter != (*dump_iter)->tids->end(); bbl_iter++)
				{
					json_array_append_number(tids, *bbl_iter);
				}

				json_object_set_number(dump_file_obj, "id", (*dump_iter)->id);
				json_object_set_number(dump_file_obj, "start", iter->second.base);
				json_object_set_number(dump_file_obj, "end", (*dump_iter)->size + iter->second.base);
				json_object_set_number(dump_file_obj, "size", (*dump_iter)->size);
				json_object_set_number(dump_file_obj, "entry", (*dump_iter)->entry);
				json_object_set_value(dump_file_obj, "tids", tids_val);
				json_array_replace_value(mem_dumps, (*dump_iter)->id, dump_file_val);
			}
		}

		json_object_set_value(root_object, "mem_areas", mem_dumps_val);
	}

	return false;
}

bool save_calls(JSON_Object *root_object, map<ADDRINT, CALL_INFO> &calls)
{
	ADDRINT call_index = 0, api_index = 0;
	map<ADDRINT, CALL_INFO>::iterator citer;
	list<ADDRINT>::iterator callee, callee_id;
	map<ADDRINT, CALL_ITEM>::iterator callee2;

	if (calls.begin() == calls.end())
		return false;

	JSON_Value *calls_val = json_value_init_array();
	JSON_Array *calls_ar = json_value_get_array(calls_val);

	for (citer = calls.begin(); citer != calls.end(); citer++)
	{
		JSON_Value *callees_val = json_value_init_array();
		JSON_Array *callees = json_value_get_array(callees_val);
		JSON_Value *bbl_ids_val = json_value_init_array();
		JSON_Array *bbl_ids = json_value_get_array(bbl_ids_val);
		JSON_Value *call_val = json_value_init_object();
		JSON_Object *call = json_value_get_object(call_val);

		for (callee2 = citer->second.callees.begin(); callee2 != citer->second.callees.end(); callee2++)
		{
			JSON_Value *callee_val = json_value_init_object();
			JSON_Object *callee = json_value_get_object(callee_val);
			JSON_Value *callees_ids_val = json_value_init_array();
			JSON_Array *callees_ids = json_value_get_array(callees_ids_val);

			for (callee_id = callee2->second.ids.begin(); callee_id != callee2->second.ids.end(); callee_id++)
			{
				json_array_append_number(callees_ids, *callee_id);
			}

			json_object_set_number(callee, "addr", callee2->first);
			json_object_set_number(callee, "execs", callee2->second.ids.size());
			json_object_set_value(callee, "ids", callees_ids_val);

			json_array_append_value(callees, callee_val);
		}

		json_object_set_number(call, "execs", citer->second.execs);
		json_object_set_value(call, "callees", callees_val);
		json_object_set_value(call, "bbl_ids", bbl_ids_val);
		json_object_set_string(call, "name", citer->second.name);
		json_object_set_number(call, "target", citer->first);
		json_object_set_number(call, "is_reg", citer->second.isRegBased);

		json_array_append_value(calls_ar, call_val);
	}

	json_object_set_value(root_object, "calls", calls_val);

	return true;
}

bool save_thread_aux(JSON_Object *root_object, ADDRINT tid)
{	
	json_object_set_number(root_object, "tid", tid);
	json_object_set_number(root_object, "tfunc", tfuncs[tid]);

	return true;
}

void save_api_log(JSON_Object *root_object, ADDRINT tid)
{
	std::list<API_LOG>::iterator iter;
	JSON_Value *api_params_val = json_value_init_array();
	JSON_Array *api_params_ar = json_value_get_array(api_params_val);

	for(iter = tid_api_params_log[tid].begin(); iter != tid_api_params_log[tid].end(); iter++)
	{
		JSON_Value *api_val = json_value_init_object();
		JSON_Object *api = json_value_get_object(api_val);
		JSON_Value *param_val = json_parse_string(iter->params.c_str());

		json_object_set_number(api, "xref", (double)iter->ret_addr);
		json_object_set_number(api, "tid", (double)iter->tid);
		json_object_set_number(api, "id", (double)iter->id);
		json_object_set_number(api, "target", (double)iter->addr);
		json_object_set_string(api, "name", iter->name.c_str());
		json_object_set_value(api, "parameters", param_val);

		json_array_append_value(api_params_ar, api_val);
	}

	json_object_set_value(root_object, "api_parameters", api_params_val);
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*
Maze output format:
[
	{
		"name":			 "explorer",
		"pid":			 "111",
		"threads_num":	 "5",
		"mem_areas": [
			{
				"start":			"0x40000",
				"end":				"0x50000",
				"entry"				"0x45000",
				"tids":				[]
			}
		],
		"threads": [
			{
				"bbls":	 [
					{
						"start": 0,
						"end":	 0,
						"inst":	 1,
						"reps":	 5,
						"ret":	 1
					}
				],
				"calls": [
					{
						"target":	1234,
						"is_reg":	1,
						"execs":	4,
						"callees":	[ {"ref": 0x123456, "execs": 1} ],
						"bbl_ids":	[]
					}
				],
				"api_params": [
					{
					}
				]
			}
		]
	}
]
*/

void save_maze_log()
{
	PIN_LockClient();

	JSON_Value *maze_val = json_value_init_array();
	JSON_Array *maze = json_value_get_array(maze_val);

	JSON_Value *threads_val = json_value_init_array();
	JSON_Array *threads = json_value_get_array(threads_val);

	JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

	string json_fname = cfg.output_dir + "\\maze_walk_" + decstr((UINT32)W::GetCurrentProcessId()) + ".json";

	// process information
	{
		JSON_Value *process_obj_val = json_value_init_object();
		JSON_Object *process_obj = json_value_get_object(process_obj_val);

		json_object_set_string(process_obj, "name", "");
		json_object_set_number(process_obj, "pid", (UINT32)W::GetCurrentProcessId());
		json_object_set_number(process_obj, "threads_num", thread_num);

		for (int i = 0; i < THREAD_LIMIT; i++)
		{
			if (!!tid_basic_blocks[i].size())
			{
				JSON_Value *thread_value = json_value_init_object();
				JSON_Object *thread_object = json_value_get_object(thread_value);

				// save basic data before the memory area
				save_thread_aux(thread_object, i);
				save_bbls(thread_object, tid_basic_blocks[i]);
				save_calls(thread_object, tid_calls[i]);

				#ifdef OS32
				save_api_log(thread_object, i);
				#endif

				json_array_append_value(threads, thread_value);
			}
		}

		json_object_set_value(process_obj, "threads", threads_val);
		save_mas(process_obj);

		json_object_set_value(root_object, "process", process_obj_val);
		json_array_append_value(maze, root_value);
	}
	PIN_UnlockClient();

	json_serialize_to_file_pretty(maze_val, json_fname.c_str());
	json_value_free(maze_val);
}
