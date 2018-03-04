#include <string>
#include <map>
#include <fstream>
#include <algorithm>
#include "json\json.h"
#include "cfg.h"
#include <Windows.h>
#include "Logger.h"


namespace MazeWalker {

    CFG::CFG() {
        _cfg_data = _hook_data = 0;
    }

    bool CFG::Load(const char* path) {
        std::ostringstream log_path, trace_fname, scripts_path;

        if (_cfg_data)
            return true;

        if (path) {
            _cfg_data = new Json::Value();
            if (_cfg_data) {
                std::ifstream file(path);
                file >> (*(Json::Value*)_cfg_data);

                _hook_data = new std::map<std::string, std::map<std::string, ApiHook>>;
                if (_hook_data) {
                    std::map<std::string, std::map<std::string, ApiHook*>>& hook_data = 
                        *((std::map<std::string, std::map<std::string, ApiHook*>>*)_hook_data);

                    Json::Value& cfg_data = (*(Json::Value*)_cfg_data);
                    for (unsigned i = 0; i < cfg_data["api_monitor"]["apis"].size(); i++) {
                        Json::Value& apis = cfg_data["api_monitor"]["apis"][i];
                        std::string lib = apis["lib"].asString();
                        std::string api_name = apis["name"].asString();
                        std::transform(lib.begin(), lib.end(), lib.begin(), ::tolower);
                        std::transform(api_name.begin(), api_name.end(), api_name.begin(), ::tolower);
                        hook_data[lib][api_name] = new ApiHook(apis["lib"].asCString(),
                                                               apis["name"].asCString(),
                                                               strlen(apis["pre_parser"].asCString()) ? apis["pre_parser"].asCString() : 0,
                                                               strlen(apis["post_parser"].asCString()) ? apis["post_parser"].asCString() : 0,
                                                               apis["num"].asInt());
                    }

                    log_path << getOutputDir() << "\\maze_log_" << GetCurrentProcessId() << ".txt";
                    log_file_path = _strdup(log_path.str().c_str());
                    trace_fname << getOutputDir() << "\\maze_walk_" << GetCurrentProcessId() << ".json";
                    trace_log = _strdup(trace_fname.str().c_str());

                    root_dir = _strdup((*(Json::Value*)_cfg_data)["pintool_dir"].asCString());
                    scripts_path << root_dir << "\\PyScripts\\";
                    scripts_dir = _strdup(scripts_path.str().c_str());

                    return true;
                }
            }
        }
        return false;
    }

    CFG& CFG::Instance() {
        static CFG config;
        return config;
    }

    bool CFG::PreloadLibraries() const {
        Json::Value& cfg_data = (*(Json::Value*)_cfg_data);
        for (unsigned i = 0; i < cfg_data["preload_libs32"].size(); i++) {
            HMODULE mod = LoadLibraryA(cfg_data["preload_libs32"][i].asCString());
            if (mod == NULL) {
                Logger::Instance().Write("[%s] Library preload failed for %s\n", __FUNCTION__, 
                                         cfg_data["preload_libs32"][i].asCString());
                return false;
            }
        }
        return true;
    }

    bool CFG::isHashWhitelisted(const char* hash) const {
        if (hash && strlen(hash) > 0) {
            std::string _hash(hash);

            for (unsigned i = 0; i < (*(Json::Value*)_cfg_data)["whitelist"]["imphash"].size(); i++) {
                if ((*(Json::Value*)_cfg_data)["whitelist"]["imphash"][i]["hash"].asString() == _hash)
                    return true;
            }

            for (unsigned i = 0; i < (*(Json::Value*)_cfg_data)["whitelist"]["exphash"].size(); i++) {
                if ((*(Json::Value*)_cfg_data)["whitelist"]["exphash"][i]["hash"].asString() == _hash)
                    return true;
            }
        }

        return false;
    }

    bool CFG::isPathWhitelisted(const char* path) const {
        if (path && strlen(path) > 0) {
            for (unsigned i = 0; i < (*(Json::Value*)_cfg_data)["whitelist"]["path"].size(); i++) {
                const char* wpath = (*(Json::Value*)_cfg_data)["whitelist"]["path"][i].asCString();
                if (_strnicmp(path, wpath, strlen(wpath)) == 0) {
                    return true;
                }
            }
        }

        return false;
    }

    bool CFG::isModuleWhitelisted(const char* name) const {
        if (name && strlen(name)) {
            for (unsigned i = 0; i < (*(Json::Value*)_cfg_data)["whitelist"]["mods"].size(); i++) {
                const char* wname = (*(Json::Value*)_cfg_data)["whitelist"]["mods"][i].asCString();
                if (_strnicmp(name, wname, strlen(wname)) == 0) {
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

        std::transform(loclib.begin(), loclib.end(), loclib.begin(), ::tolower);
        it = hook_data.find(loclib);
        if (it != hook_data.end()) {
            std::string locapi = std::string(api);
            std::transform(locapi.begin(), locapi.end(), locapi.begin(), ::tolower);
            it2 = it->second.find(locapi);
            if (it2 != it->second.end()) {
                return it2->second;
            }
        }

        return NULL;
    }

    const char* CFG::getScriptsDir() const {
        return scripts_dir;
    }

    const char* CFG::getOutputDir() const {
        return (*(Json::Value*)_cfg_data)["out_dir"].asCString();
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