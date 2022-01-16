#include "pin.H"
#include "ProcessTrace.h"
#include "BBL.h"
#include <list>
#include <map>
#include <vector>
#include "cfg.h"
#include "cJSON.h"
#include "PythonInternal.h"
#include "Logger.h"
#include "PEImage.h"
#include "WinAddress.h"
#include "Blob.h"


namespace MazeWalker {

    typedef struct _mod_info {
        bool doTrace;
        Image* img;
    } MOD_INFO, *PMOD_INFO;

    ProcessTrace::ProcessTrace(const char* cfg_path) : cfg(cfg_path) {
        _mas = new std::map<int, MemoryArea*>;
        modules = new std::vector<PMOD_INFO>;

        Logger::Write("%s - _mas = %p, modules = %p\n", __FUNCTION__, _mas, modules);
    }

    bool ProcessTrace::Initialize() {
        if (LoadPython()) {
            pPy_Initialize();

            if (pPy_IsInitialized() > 0) {
                PyObject* sysPath = pPySys_GetObject((char*)"path");
                pPyList_Append(sysPath, pPyString_FromString(cfg.getScriptsDir()));
                Logger::Write("Python Initialized!\n");
                return true;
            }
            else {
                Logger::Write("Python initialization error!\n");
            }
        }
        else {
            Logger::Write("Python DLL load error!\n");
        }

        return false;
    }

    ProcessTrace::~ProcessTrace() {
        if (pPy_IsInitialized() > 0)
            pPy_Finalize();
    }

    MemoryArea* ProcessTrace::addMemoryArea(int address) {
        std::vector<PMOD_INFO>::iterator mod_it;
        IAddress *addr = new WinAddress(address);

        std::map<int, MemoryArea*>& mas = *((std::map<int, MemoryArea*>*)_mas);
        std::map<int, MemoryArea*>::iterator it = mas.find(addr->Base());

        if (it != mas.end()) {
            return it->second;
        }

        for (mod_it = ((std::vector<PMOD_INFO>*)modules)->begin();
            mod_it != ((std::vector<PMOD_INFO>*)modules)->end(); mod_it++) {
            if ((*mod_it)->img != NULL && (*mod_it)->img->Base() == addr->Base()) {
                return (*mod_it)->img;
            }
        }
        
        Logger::Write("[%s] Adding memory area : 0x%x\n", __FUNCTION__, addr->Base());

        if (PEImage::isValid((char*)(addr->Base()), addr->Size())) {
            PMOD_INFO head = new MOD_INFO;
            if (head) {
                head->doTrace = true;
                head->img = new PEImage(address, NULL);
                ((std::vector<PMOD_INFO>*)modules)->push_back(head);
                if (cfg.isHashWhitelisted(head->img->ImpHash()) || cfg.isHashWhitelisted(head->img->ExpHash()))
                    head->doTrace = false;
                else {
                    Logger::Write("Unknown image found! ImpHash = %s ExpHash = %s\n", head->img->ImpHash(), head->img->ExpHash());
                    mas[addr->Base()] = head->img;
                }
                return head->img;
            }
        }
        else {
            mas[addr->Base()] = new Blob(address);
            return mas[addr->Base()];
        }

        Logger::Write("Failed to add memory are!\n");

        return NULL;
    }

    const char* ProcessTrace::ResolveAddress(int address) {
        std::vector<PMOD_INFO>::iterator it;
        for (it = ((std::vector<PMOD_INFO>*)modules)->begin();
            it != ((std::vector<PMOD_INFO>*)modules)->end(); it++) {
            if (address > (*it)->img->Base() && ((*it)->img->Base() + (*it)->img->Size()) > address) {
                return (*it)->img->Resolve(address);
            }
        }
        return NULL;
    }

    void ProcessTrace::addImage_(void* imgObj) {
        std::vector<PMOD_INFO>::iterator it;
        PMOD_INFO head;
        int base, size, entry;
        const char* path;

        if (imgObj == NULL)
            return;

        if (IMG_Valid(*((IMG*)imgObj))) {
            base = IMG_StartAddress(*((IMG*)imgObj));

            for (it = ((std::vector<PMOD_INFO>*)modules)->begin();
                it != ((std::vector<PMOD_INFO>*)modules)->end(); it++) {
                if ((*it)->img->Base() == base) {
                    return;
                }
            }

            size = IMG_HighAddress(*((IMG*)imgObj)) - IMG_LowAddress(*((IMG*)imgObj));
            entry = IMG_EntryAddress(*((IMG*)imgObj));
            path = IMG_Name(*((IMG*)imgObj)).c_str();
            Logger::Write("Path: %s, base=0x%x, size=0x%x\n", path, base, size);

            head = new MOD_INFO;
            if (head) {
                head->doTrace = true;
                head->img = new PEImage(entry, path);

                if (cfg.isPathWhitelisted(head->img->Path()) || cfg.isModuleWhitelisted(head->img->Name()) ||
                    cfg.isHashWhitelisted(head->img->ImpHash()) || cfg.isHashWhitelisted(head->img->ExpHash())) {
                    head->doTrace = false;
                    Logger::Write("[%s] \t Image was whitelisted. ImpHash = %s\n", __FUNCTION__, head->img->ImpHash());
                }

                if (head->doTrace) {
                    std::map<int, MemoryArea*>& mas = *((std::map<int, MemoryArea*>*)_mas);
                    std::map<int, MemoryArea*>::iterator it = mas.find(base);

                    if (it == mas.end()) {
                        mas[base] = head->img;
                    }
                }

                ((std::vector<PMOD_INFO>*)modules)->push_back(head);
                Logger::Write("[%s] Adding image : %s, 0x%x\n", __FUNCTION__, head->img->Path(), head->img->Base());
                return;
            }
        }

        Logger::Write("Failed to add image \n");
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
        std::ostringstream dump_prefix;
        
        dump_prefix << dir << "\\" << PIN_GetPid();
        for (it = ((std::map<int, MemoryArea*>*)_mas)->begin(); 
             it != ((std::map<int, MemoryArea*>*)_mas)->end(); it++) {
                 (*it).second->Dump(dump_prefix.str().c_str());
        }
    }

    bool ProcessTrace::toJson( void* root) const {
        Logger::Write("%s\n", __FUNCTION__);
        std::map<int, MemoryArea*>::iterator it;

        Logger::Write("Mem areas: %d\n", ((std::map<int, MemoryArea*>*)_mas)->size());
        cJSON_AddNumberToObject( (cJSON*)root, "pid", PIN_GetPid());
        cJSON* mas = cJSON_AddArrayToObject((cJSON*)root, "mem_areas");

        for (it = ((std::map<int, MemoryArea*>*)_mas)->begin(); 
                it != ((std::map<int, MemoryArea*>*)_mas)->end(); it++) {
                    (*it).second->toJson(mas);
        }

        return true;
    }
}