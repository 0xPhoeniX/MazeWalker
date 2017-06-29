#ifndef _MAZEWARKER_CFG_H_
#define _MAZEWARKER_CFG_H_

#include <string>
#include <vector>

typedef struct {
	std::string name;
	std::string lib;
	std::string pre_parser;
	std::string post_parser;
	short vars_num;
} API_LOG_ITEM;

typedef struct _MAZE_CFG {
	std::vector<std::string> hash_whitelist;
	std::vector<std::string> path_whitelist;
	std::vector<std::string> mods_whitelist;
	std::vector<API_LOG_ITEM> api_to_log;
	std::string script_path;
	std::string output_dir;
	std::string pin32dir;
	std::string pin64dir;
} MAZE_CFG;

extern MAZE_CFG cfg;

// load mazewalker configuration file
//		path - path to the file
int load_cfg(const char* path);

#endif