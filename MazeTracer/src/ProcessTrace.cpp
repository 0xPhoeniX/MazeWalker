#include "ProcessTrace.h"
#include "BBL.h"
#include <list>
#include <map>
#include <vector>
#include "pin.H"
#include "cfg.h"
#include "Logger.h"


namespace MazeWalker {

    typedef struct _mod_info {
        bool doTrace;
        Image* img;
    } MOD_INFO, *PMOD_INFO;

    ProcessTrace::ProcessTrace() {
        _mas = new std::map<int, MemoryArea*>;
        modules = new std::vector<PMOD_INFO>;
    }

    ProcessTrace& ProcessTrace::Instance() {
        static ProcessTrace tracer;
        return tracer;
    }

    bool ProcessTrace::Initialize(const char* config_file) {
        if (CFG::Instance().Load(config_file) &&
            CFG::Instance().PreloadLibraries()) {
                return true;
        }

        return false;
    }

    void ProcessTrace::addMemoryArea(MemoryArea* ma) {

        if (ma == NULL)
            return;
        
        std::map<int, MemoryArea*>& mas = *((std::map<int, MemoryArea*>*)_mas);
        std::map<int, MemoryArea*>::iterator it = mas.find(ma->Base());

        if (it == mas.end()) {
            Logger::Instance().Write("[%s] Adding memory region: 0x%x\n", __FUNCTION__, ma->Base());
            mas[ma->Base()] = ma;
        }
    }

    void ProcessTrace::addImage(Image* img) {
        std::vector<PMOD_INFO>::iterator it;
        PMOD_INFO head;

        if (img == NULL)
            return;

        for (it = ((std::vector<PMOD_INFO>*)modules)->begin(); 
             it != ((std::vector<PMOD_INFO>*)modules)->end(); it++) {
                if ((*it)->img->Base() == img->Base()) {
                    return;
                }
        }

        Logger::Instance().Write("[%s] Adding image: %s, %s, 0x%x\n", __FUNCTION__, img->Path(), img->ImpHash(), img->Base());

        head = new MOD_INFO;
        if (head) {
            head->doTrace = true;
            head->img = img;

            if (CFG::Instance().isPathWhitelisted(img->Path()) ||
                CFG::Instance().isModuleWhitelisted(img->Name()) ||
                CFG::Instance().isHashWhitelisted(img->ImpHash()) || 
                CFG::Instance().isHashWhitelisted(img->ExpHash())) {
                    Logger::Instance().Write("[%s] \t Image was whitelisted.\n", __FUNCTION__);
                    head->doTrace = false;
            }

            ((std::vector<PMOD_INFO>*)modules)->push_back(head);
        }
    }

    bool ProcessTrace::isAddressInScope(int address) const {
        std::vector<PMOD_INFO>::iterator it;

        if (address) {
            for (it = ((std::vector<PMOD_INFO>*)modules)->begin(); 
                 it != ((std::vector<PMOD_INFO>*)modules)->end(); it++) {
                     if (address > (*it)->img->Base() && address < ((*it)->img->Size() + (*it)->img->Base())) {
                         return (*it)->doTrace;
                     }
            }
        }

        return true;
    }

    void ProcessTrace::Export(const char* dir) const {
        std::map<int, MemoryArea*>::iterator it;
        ostringstream dump_prefix;
        
        dump_prefix << dir << "\\" << PIN_GetPid();
        for (it = ((std::map<int, MemoryArea*>*)_mas)->begin(); 
             it != ((std::map<int, MemoryArea*>*)_mas)->end(); it++) {
                 (*it).second->Dump(dump_prefix.str().c_str());
        }
    }

    bool ProcessTrace::toJson( Json::Value& root) const {
        std::map<int, MemoryArea*>::iterator it;

        if (((std::map<int, MemoryArea*>*)_mas)->size() > 0) {
            root["pid"] = PIN_GetPid();
            root["mem_areas"] = Json::Value(Json::arrayValue);

            for (it = ((std::map<int, MemoryArea*>*)_mas)->begin(); 
                 it != ((std::map<int, MemoryArea*>*)_mas)->end(); it++) {
                     (*it).second->toJson(root["mem_areas"]);
            }
        }

        return true;
    }
}