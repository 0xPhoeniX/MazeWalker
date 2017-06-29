#ifndef _MAZEWARKER_PYTHON_H_
#define _MAZEWARKER_PYTHON_H_


// prepare and load python interpreter
//		script_base_dir - path to the directory with filter scripts
int load_python(const char* script_base_dir);

// execute python script callback for an api
//		modure - python script module (py file)
//		func_name - function to execute from the module
//		param_num - number of the parameters for the filtered api
//		params - pointer to the stack with the api parameters
//		err - err to be returned from the script
char* call_analyzer(const char* module, const char* func_name, short param_num, long* params, char **err);

// unload python interpreter
void unload_python();


#endif