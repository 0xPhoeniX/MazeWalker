#include "Thread.h"
#include <set>
#include <map>
#include <list>
#include "cJSON.h"
#include "Logger.h"


namespace MazeWalker {

    Thread::Thread(int entry, int id) {
        _entry = entry;
        _id = id;
        _bbl_lut = new std::map<int, BasicBlock*>;
        _bbls = new std::list<BasicBlock*>;
        _call_lut = new std::map<int, Call*>;
        _calls = new std::list<Call*>;
    }

    Thread::~Thread() {
        if (_bbls) {
            delete _bbls;
        }
        if (_call_lut) {
            delete _call_lut;
        }
        if (_bbl_lut) {
            delete _bbl_lut;
        }
        if (_calls) {
            delete _calls;
        }
    }

    void Thread::addBBL(BasicBlock *bbl) {
        (*(std::map<int, BasicBlock*>*)_bbl_lut)[bbl->getStart()] = bbl;
        (*(std::list<BasicBlock*>*)_bbls).push_back(bbl);
    }

    BasicBlock* Thread::getBBL(int start) const {
        return (*(std::map<int, BasicBlock*>*)_bbl_lut)[start];
    }

    void Thread::addCall(Call *call) {
        (*(std::map<int, Call*>*)_call_lut)[call->getTarget()] = call;
        (*(std::list<Call*>*)_calls).push_back(call);
    }

    Call* Thread::getCall(int target) const {
        return (*(std::map<int, Call*>*)_call_lut)[target];
    }

    bool Thread::toJson( void* root ) const {

        if (((std::list<Call*>*)_calls)->size() > 0 ||
            ((std::list<BasicBlock*>*)_bbls)->size() > 0) {
            cJSON_AddNumberToObject((cJSON*)root, "tid", _id);
            cJSON_AddNumberToObject((cJSON*)root, "tfunc", _entry);
            cJSON* bbls = cJSON_AddArrayToObject((cJSON*)root, "bbls");
            cJSON* calls = cJSON_AddArrayToObject((cJSON*)root, "calls");

            for (std::list<Call*>::iterator it = ((std::list<Call*>*)_calls)->begin();
                it != ((std::list<Call*>*)_calls)->end(); ++it) {
                    cJSON* json_call = cJSON_CreateObject();
                    if ((*it)->toJson(json_call))
                        cJSON_AddItemToArray(calls, json_call);
            }

            for (std::list<BasicBlock*>::iterator it = ((std::list<BasicBlock*>*)_bbls)->begin();
                it != ((std::list<BasicBlock*>*)_bbls)->end(); ++it) {
                    cJSON* json_bbl = cJSON_CreateObject();
                    if ((*it)->toJson(json_bbl))
                        cJSON_AddItemToArray(bbls, json_bbl);
            }
        }

        return true;
    }
}