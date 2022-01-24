#include "MemoryArea.h"
#include "Windows.h"
#include "cfg.h"
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <string>
#include <sstream>
#include <list>
#include <set>
#include "cJSON.h"
#include <vector>
#include "Logger.h"


#define THREAD_LIMIT 100

namespace MazeWalker {

    int _idGenerator = 0;
    int _sidGenerator = 0;

    typedef struct _layer {
        char* data;
        size_t size;
        int entry;
        int id;
        std::vector<Thread*> threads;
    } LAYER, *PLAYER;

    MemoryArea::MemoryArea(int entry) {
        _states = new std::list<PLAYER>;
        MEMORY_BASIC_INFORMATION curr_info;
        PLAYER l;
        int currAddr = 0;
        _base = _size = 0;

        if (VirtualQuery((PVOID)(entry), &curr_info, sizeof(MEMORY_BASIC_INFORMATION))) {
            currAddr = _base = (int)curr_info.AllocationBase;
            l = new LAYER;
            if (l) {
                l->threads.reserve(THREAD_LIMIT);
                for (int i = 0; i < THREAD_LIMIT; i++) { l->threads[i] = 0; }
                l->id = _idGenerator++;
                l->entry = entry;
                l->data = NULL;
                l->size = 0;

                while (VirtualQuery((PVOID)currAddr, &curr_info, sizeof(MEMORY_BASIC_INFORMATION)) && (int)curr_info.AllocationBase == _base) {
                    l->size += curr_info.RegionSize;
                    l->data = (char*)realloc(l->data, l->size);
                    if (curr_info.State == MEM_COMMIT) {
                        memcpy(l->data + ((int)curr_info.BaseAddress - _base), (void*)curr_info.BaseAddress, curr_info.RegionSize);
                    }
                    currAddr = (int)curr_info.BaseAddress + curr_info.RegionSize;
                }
                ((std::list<PLAYER>*)(_states))->push_back(l);
                _size = l->size;
            }
        }

        Logger::Write("%s - base=0x%x, entry=0x%x\n", __FUNCTION__, _base, entry);
    }

    MemoryArea::~MemoryArea() {
        std::list<PLAYER>::iterator iter;

        if (_states) {
            for (iter = ((std::list<PLAYER>*)(_states))->begin();
                iter != ((std::list<PLAYER>*)(_states))->end(); iter++) {
                free((*iter)->data);
                (*iter)->data = NULL;
            }
            ((std::list<PLAYER>*)(_states))->clear();
            delete _states;
            _states = 0;
        }
    }

    bool MemoryArea::saveState(int entry) {
        Logger::Write("%s - entry=0x%x\n", __FUNCTION__, entry);
        PLAYER l;
        MEMORY_BASIC_INFORMATION curr_info;
        int currAddr = 0;

        if (VirtualQuery((PVOID)(entry), &curr_info, sizeof(MEMORY_BASIC_INFORMATION))) {
            if (_base != (int)curr_info.AllocationBase) {
                Logger::Write("Wrong memory area: _base = 0x%x, found = 0x%x\n", _base, (int)curr_info.AllocationBase);
                return false;
            }
            currAddr = (int)curr_info.AllocationBase;
            l = new LAYER;
            if (l) {
                l->threads.reserve(THREAD_LIMIT);
                for (int i = 0; i < THREAD_LIMIT; i++) { l->threads[i] = 0; }
                l->id = _idGenerator++;
                l->entry = entry;
                l->size = 0;
                l->data = NULL;

                while (VirtualQuery((PVOID)currAddr, &curr_info, sizeof(MEMORY_BASIC_INFORMATION)) && (int)curr_info.AllocationBase == _base) {
                    l->size += curr_info.RegionSize;
                    l->data = (char*)realloc(l->data, l->size);
                    if (curr_info.State == MEM_COMMIT) {
                        memcpy(l->data + ((int)curr_info.BaseAddress - _base), (void*)curr_info.BaseAddress, curr_info.RegionSize);
                    }
                    currAddr = (int)curr_info.BaseAddress + curr_info.RegionSize;
                }
                ((std::list<PLAYER>*)(_states))->push_back(l);
                _size = l->size;
                return true;
            }
        }
        return false;
    }

    MemoryAreaStatus MemoryArea::StatusAt(int address, size_t size) const {
        int offset;
        std::list<PLAYER>::const_reverse_iterator iter;
        MEMORY_BASIC_INFORMATION curr_info;

        if (VirtualQuery((PVOID)(address), &curr_info, sizeof(MEMORY_BASIC_INFORMATION))) {
            if (_base != (int)curr_info.AllocationBase) {
                Logger::Write("Wrong memory area: _base = 0x%x, found = 0x%x\n", _base, (int)curr_info.AllocationBase);
                return Error;
            }
            iter = ((std::list<PLAYER>*)(_states))->rbegin();
            if (iter != ((std::list<PLAYER>*)(_states))->rend()) {
                if (address > _base && address < ((*iter)->size + _base)) {
                    offset = address - _base;
                    if (memcmp((void*)((*iter)->data + offset), (void*)address, size) != 0)
                        return Different;
                    else
                        return Equal;
                }
            }
        }

        return Error;
    }

    void MemoryArea::Dump(const char* path_prefix) {
        const char* ftype = getFileType();
        std::list<PLAYER>::const_iterator iter;
        FILE* dump;

        if (_states && path_prefix && strlen(path_prefix) > 0) {
            for (iter = ((std::list<PLAYER>*)(_states))->begin();
                 iter != ((std::list<PLAYER>*)(_states))->end(); iter++) {
                     std::ostringstream fpath;

                     fpath << path_prefix << "_" << (*iter)->id << std::hex << "_" << _base << "_" <<  (*iter)->size << "." << ftype;

                     dump = NULL;
                     processBeforeDump((*iter)->data, (*iter)->size);
                     dump = fopen(fpath.str().c_str(), "wb");
                     fwrite((*iter)->data, sizeof(char), (*iter)->size, dump);
                     fclose(dump);
            }
        }
    }

    Thread* MemoryArea::getThread(int id) const {
        if (_states == NULL) {
            Logger::Write("\tStates are still NULL!!!\n");
        }
        if (id < THREAD_LIMIT) {
            std::list<PLAYER>::const_reverse_iterator iter = ((std::list<PLAYER>*)(_states))->rbegin();
            return (*iter)->threads[id];
        }

        return 0;
    }

    void MemoryArea::addThread(Thread* thread) {
        if (thread && thread->ID() < THREAD_LIMIT) {
            std::list<PLAYER>::const_reverse_iterator iter = ((std::list<PLAYER>*)(_states))->rbegin();
            if ((*iter)->threads[thread->ID()] == 0) {
                (*iter)->threads[thread->ID()] = thread;
                Logger::Write("[%s] Adding record for memory region with Base=0x%x, TID=%d\n", __FUNCTION__, Base(), thread->ID());
            }
        }
    }

    const char* MemoryArea::getLatestState(size_t& size) const {
        if (_states) {
            std::list<PLAYER>::const_reverse_iterator iter = ((std::list<PLAYER>*)(_states))->rbegin();
            size = (*iter)->size;
            return (*iter)->data;
        }

        size = 0;
        return NULL;
    }

    bool MemoryArea::toJson( void* root ) const {
        Logger::Write("%s\n", __FUNCTION__);
        std::list<PLAYER>::const_iterator iter;

        if (_states == NULL) {
            Logger::Write("No states to save!\n");
            return true;
        }

        for (iter = ((std::list<PLAYER>*)(_states))->begin();
             iter != ((std::list<PLAYER>*)(_states))->end(); iter++) {
                 cJSON* json_ma = cJSON_CreateObject();
                 
                 cJSON_AddNumberToObject( json_ma, "id", (*iter)->id);
                 cJSON_AddNumberToObject(json_ma, "start", _base);
                 cJSON_AddNumberToObject(json_ma, "end", (*iter)->size + _base);
                 cJSON_AddNumberToObject(json_ma, "entry", (*iter)->entry);
                 cJSON_AddNumberToObject(json_ma, "size", (*iter)->size);
                 cJSON* threads = cJSON_AddArrayToObject(json_ma, "threads");

                 for (int i = 0; i < THREAD_LIMIT; i++) {
                    if ((*iter)->threads[i] != 0) {
                        cJSON* thread = cJSON_CreateObject();
                        if ((*iter)->threads[i]->toJson(thread))
                            cJSON_AddItemToArray(threads, thread);
                    }
                 }

                 cJSON_AddItemToArray((cJSON*)root, json_ma);
        }

        return true;
    }
}