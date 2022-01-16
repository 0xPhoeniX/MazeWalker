#include "pin.H"
#include <string>
#include <map>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <sstream>
#include "cfg.h"
#include "cJSON.h"
#include "Logger.h"

namespace MazeWalker {

    CFG::CFG(const char* path) {
        _cfg_data = _hook_data = 0;
        char* tmp_data = NULL;
        int fsize = 0;
        cJSON* cfg_json = NULL;
        

        if (path) {
            FILE* fcfg = fopen(path, "r");
            if (fcfg) {
                fseek(fcfg, 0, SEEK_END);
                fsize = ftell(fcfg);
                tmp_data = (char*)malloc(fsize);
                fseek(fcfg, 0, SEEK_SET);
                if (tmp_data) {
                    fread(tmp_data, 1, fsize, fcfg);
                    fclose(fcfg);
                    fcfg = NULL;
                    cfg_json = cJSON_Parse((char*)tmp_data);
                    free(tmp_data);
                    tmp_data = NULL;
                    _cfg_data = cfg_json;
                }
            }

            out_dir_path = _strdup(cJSON_GetStringValue(cJSON_GetObjectItem(cfg_json, "out_dir")));
            std::string log_path = std::string(out_dir_path) + "\\maze_log_" + decstr(PIN_GetPid()) + ".txt";
            log_file_path = _strdup(log_path.c_str());
            Logger::Write("Log file: %s\n", log_file_path);
            std::string trace_fname = std::string(out_dir_path) + "\\maze_walk_" + decstr(PIN_GetPid()) + ".json";
            trace_log = _strdup(trace_fname.c_str());
            Logger::Write("Trace file: %s\n", trace_log);

            root_dir = _strdup(cJSON_GetStringValue(cJSON_GetObjectItem(cfg_json, "pintool_dir")));
            std::string scripts_path = std::string(root_dir) + "\\PyScripts\\";
            scripts_dir = _strdup(scripts_path.c_str());
            Logger::Write("Scripts dir: %s\n", scripts_dir);

            _hook_data = new std::map<std::string, std::map<std::string, ApiHook>>;
            if (_hook_data && cfg_json) {
                std::map<std::string, std::map<std::string, ApiHook*>>& hook_data =
                    *((std::map<std::string, std::map<std::string, ApiHook*>>*)_hook_data);

                cJSON* api_list = cJSON_GetObjectItem(cJSON_GetObjectItem(cfg_json, "api_monitor"), "apis");
                for (unsigned i = 0; i < cJSON_GetArraySize(api_list); i++) {
                    cJSON* api = cJSON_GetArrayItem(api_list, i);
                    std::string lib = cJSON_GetStringValue(cJSON_GetObjectItem(api, "lib"));
                    std::string api_name = cJSON_GetStringValue(cJSON_GetObjectItem(api, "name"));
                    std::string pre_parser = cJSON_GetStringValue(cJSON_GetObjectItem(api, "pre_parser"));
                    std::string post_parser = cJSON_GetStringValue(cJSON_GetObjectItem(api, "post_parser"));
                    std::transform(lib.begin(), lib.end(), lib.begin(), ::toupper);
                    std::transform(api_name.begin(), api_name.end(), api_name.begin(), ::tolower);
                    hook_data[lib][api_name] = new ApiHook(_strdup(lib.c_str()), _strdup(api_name.c_str()),
                        pre_parser.size() ? _strdup(pre_parser.c_str()) : NULL,
                        post_parser.size() ? _strdup(post_parser.c_str()) : NULL,
                        cJSON_GetNumberValue(cJSON_GetObjectItem(api, "num")));
                    Logger::Write("Parsed: %s@%s\n", hook_data[lib][api_name]->lib, hook_data[lib][api_name]->name);
                }
            }
        }
        Logger::Write("Config loaded!\n");
    }

    bool CFG::PreloadLibraries() const {
        /*Json::Value& cfg_data = (*(Json::Value*)_cfg_data);
        for (unsigned i = 0; i < cfg_data["preload_libs32"].size(); i++) {
            HMODULE mod = LoadLibraryA(cfg_data["preload_libs32"][i].asCString());
            if (mod == NULL) {
                Logger::Instance().Write("[%s] Library preload failed for %s\n", __FUNCTION__, 
                                         cfg_data["preload_libs32"][i].asCString());
                return false;
            }
        }*/
        return true;
    }

    bool CFG::isHashWhitelisted(const char* hash) const {
        if (hash && strlen(hash) > 0) {
            std::string _hash(hash);

            cJSON* whitelist_imphash = cJSON_GetObjectItem(cJSON_GetObjectItem((cJSON*)_cfg_data, "whitelist"), "imphash");
            for (unsigned i = 0; i < cJSON_GetArraySize(whitelist_imphash); i++) {
                cJSON* _imphash_obj = cJSON_GetArrayItem(whitelist_imphash, i);
                char* p = cJSON_GetStringValue(cJSON_GetObjectItem(_imphash_obj, "hash"));
                if (_strnicmp(hash, p, strlen(p)) == 0) {
                    Logger::Write("Mod whitelisted by imphash: %s\n", cJSON_GetStringValue(cJSON_GetObjectItem(_imphash_obj, "name")));
                    return true;
                }
            }

            cJSON* whitelist_exphash = cJSON_GetObjectItem(cJSON_GetObjectItem((cJSON*)_cfg_data, "whitelist"), "exphash");
            for (unsigned i = 0; i < cJSON_GetArraySize(whitelist_exphash); i++) {
                cJSON* _exphash_obj = cJSON_GetArrayItem(whitelist_exphash, i);
                char* p = cJSON_GetStringValue(cJSON_GetObjectItem(_exphash_obj, "hash"));
                if (_strnicmp(hash, p, strlen(p)) == 0) {
                    Logger::Write("Mod whitelisted by exphash: %s\n", cJSON_GetStringValue(cJSON_GetObjectItem(_exphash_obj, "name")));
                    return true;
                }
            }
        }

        return false;
    }

    bool CFG::isPathWhitelisted(const char* path) const {
        if (path && strlen(path) > 0) {
            cJSON* whitelist_path = cJSON_GetObjectItem(cJSON_GetObjectItem((cJSON*)_cfg_data, "whitelist"), "path");
            for (unsigned i = 0; i < cJSON_GetArraySize(whitelist_path); i++) {
                cJSON* _path = cJSON_GetArrayItem(whitelist_path, i);
                char* p = cJSON_GetStringValue(_path);
                Logger::Write("[%s] %s <-> %s\n", __FUNCTION__, path, p);
                if (strstr(path, p) != NULL) {
                    Logger::Write("Path whitelisted: %s\n", path);
                    return true;
                }
            }
        }

        return false;
    }

    bool CFG::isModuleWhitelisted(const char* name) const {
        if (name && strlen(name)) {
            cJSON* whitelist_mods = cJSON_GetObjectItem(cJSON_GetObjectItem((cJSON*)_cfg_data, "whitelist"), "mods");
            for (unsigned i = 0; i < cJSON_GetArraySize(whitelist_mods); i++) {
                cJSON* _mod = cJSON_GetArrayItem(whitelist_mods, i);
                char* p = cJSON_GetStringValue(_mod);
                if (_strnicmp(name, p, strlen(p)) == 0) {
                    Logger::Write("Mod whitelisted: %s\n", name);
                    return true;
                }
            }
        }

        return false;
    }

    const ApiHook* CFG::getHook(const char* lib, const char* api) const {
        std::map<std::string, std::map<std::string, ApiHook*>>& hook_data =
            *((std::map<std::string, std::map<std::string, ApiHook*>>*)_hook_data);

        std::map<std::string, std::map<std::string, ApiHook*>>::iterator it;
        std::map<std::string, ApiHook*>::iterator it2;
        std::string loclib = std::string(lib);

        std::transform(loclib.begin(), loclib.end(), loclib.begin(), ::toupper);
        it = hook_data.find(loclib);
        if (it != hook_data.end()) {
            std::string locapi = std::string(api);
            std::transform(locapi.begin(), locapi.end(), locapi.begin(), ::tolower);
            it2 = it->second.find(locapi);
            if (it2 != it->second.end()) {
                Logger::Write("[%s] Hook found: %s\n", __FUNCTION__, api);
                return it2->second;
            }
        }

        return NULL;
    }

    const char* CFG::getScriptsDir() const {
        return scripts_dir;
    }

    const char* CFG::getOutputDir() const {
        return out_dir_path;
    }

    const char* CFG::getRootDir() const {
        return root_dir;
    }

    const char* CFG::getLogFilePath() const {
        return log_file_path;
    }

    const char* CFG::getTraceLogFilePath() const {
        return trace_log;
    }
}