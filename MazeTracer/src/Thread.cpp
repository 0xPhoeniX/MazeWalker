#include "Thread.h"
#include <set>
#include <map>
#include <list>


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

    bool Thread::toJson( Json::Value& root ) const {

        if (((std::list<Call*>*)_calls)->size() > 0 ||
            ((std::list<BasicBlock*>*)_bbls)->size() > 0) {
            root["tid"] = _id;
            root["tfunc"] = _entry;
            root["bbls"] = Json::Value(Json::arrayValue);
            root["calls"] = Json::Value(Json::arrayValue);

            for (std::list<Call*>::iterator it = ((std::list<Call*>*)_calls)->begin();
                it != ((std::list<Call*>*)_calls)->end(); ++it) {
                    Json::Value json_call;
                    (*it)->toJson(json_call);
                    if (!json_call.empty())
                        root["calls"].append(json_call);
            }

            for (std::list<BasicBlock*>::iterator it = ((std::list<BasicBlock*>*)_bbls)->begin();
                it != ((std::list<BasicBlock*>*)_bbls)->end(); ++it) {
                    Json::Value json_bbl;
                    (*it)->toJson(json_bbl);
                    if (!json_bbl.empty())
                        root["bbls"].append(json_bbl);
            }
        }

        return true;
    }
}