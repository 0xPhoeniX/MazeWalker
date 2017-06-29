#include <string>
#include <list>
#include "cfg.h"
#include "parson.h"
#include "mazewarker.h"

using namespace std;

MAZE_CFG cfg;

int load_cfg(const char* path)
{
	JSON_Value *root_value = json_parse_file(path);
	if (root_value) {
		JSON_Object *root_object = json_value_get_object(root_value);

		JSON_Object* whitelist = json_object_get_object (root_object, "whitelist");
		JSON_Object* api_mon = json_object_get_object (root_object, "api_monitor");

		if (whitelist == NULL ||
			api_mon == NULL)
			goto err;

		JSON_Array* apis = json_object_get_array (api_mon, "apis");
		cfg.script_path = json_object_get_string(api_mon, "script_path");
		cfg.pin32dir = json_object_get_string(root_object, "pin32_dir");
		cfg.pin64dir = json_object_get_string(root_object, "pin64_dir");
		size_t api_list_size = json_array_get_count(apis);
		for(int i = 0; i < api_list_size; i++) {
			JSON_Object* item = json_array_get_object(apis, i);
			if (item) {
				API_LOG_ITEM api;
				api.name = json_object_get_string(item, "name");
				api.lib = json_object_get_string(item, "lib");
				api.pre_parser = json_object_get_string(item, "pre_parser");
				api.post_parser = json_object_get_string(item, "post_parser");
				api.vars_num = (short)json_object_get_number(item, "num");
				cfg.api_to_log.push_back(api);
			}
		}

		// It's needed to whitelist PE files which are loaded unconventionaly and we do not get notification about
		JSON_Array *imphash = json_object_get_array(whitelist, "imphash");
		JSON_Array *exphash = json_object_get_array(whitelist, "exphash");
		JSON_Array *path = json_object_get_array(whitelist, "path");
		JSON_Array *mods = json_object_get_array(whitelist, "mods");

		if (imphash == NULL ||
			exphash == NULL ||
			path == NULL	||
			mods == NULL)
			goto err;
		
		size_t imphash_size = json_array_get_count(imphash);
		for(int i = 0; i < imphash_size; i++) {
			JSON_Object* item = json_array_get_object(imphash, i);
			if (item) {
				string hash = json_object_get_string(item, "hash");
				cfg.hash_whitelist.push_back(hash);
			}
		}

		size_t exphash_size = json_array_get_count(exphash);
		for(int i = 0; i < exphash_size; i++) {
			JSON_Object* item = json_array_get_object(exphash, i);
			if (item) {
				string hash = string(json_object_get_string(item, "hash"));
				cfg.hash_whitelist.push_back(hash);
			}
		}

		size_t path_size = json_array_get_count(path);
		for(int i = 0; i < path_size ; i++) {
			string item = string(json_array_get_string(path, i));
			cfg.path_whitelist.push_back(item);
		}

		size_t mods_size = json_array_get_count(mods);
		for(int i = 0; i < mods_size ; i++) {
			string item = string(json_array_get_string(mods, i));
			cfg.mods_whitelist.push_back(item);
		}

		return 1;
	}

err:
	return 0;
}