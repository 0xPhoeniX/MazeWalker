#include "Call.h"
#include "Image.h"
#include "MemoryTracer.h"
#include <string>
#include <map>
#include <vector>


namespace MazeWalker {

    class _xref {
    public:
        _xref() : ref(0), exec(0) {}
        _xref(int r, int e) : ref(r), exec(e) { }
        int ref;
        int exec;
        std::vector<int> order;
        std::vector<IReportObject*> params;
    };

    Call::Call(int target, int xref) {
        MazeWalker::Image* img = NULL;
        MemoryArea* ma = NULL;

        _target = target;
        _xrefs = new std::map<int, _xref>;
        _params = new std::map<int, IReportObject*>;
        _order = new std::vector<int>;
        _execs = 0;
        _name = 0;
        _image = 0;
        ma = MemoryTracer::Instance().getMemoryArea(target);
        if (img = dynamic_cast<MazeWalker::Image*>(ma)) {
            _name = img->Resolve(target);
            _image = img->Name();
        }
        addXref(xref);
    }

    Call::~Call() {
        if (_xrefs) {
            delete[] _xrefs; _xrefs = 0;
        }

        if (_params) {
            delete[] _params; _params = 0;
        }

        if (_order) {
            delete[] _order; _order = 0;
        }
    }

    void Call::addXref(int xref) {
        if (((std::map<int, _xref>*)_xrefs)->find(xref) == 
            ((std::map<int, _xref>*)_xrefs)->end()) {
                (*((std::map<int, _xref>*)_xrefs))[xref] = _xref(xref, 0);
        }
        (*((std::map<int, _xref>*)_xrefs))[xref].exec++;
        (*((std::vector<int>*)_order)).push_back(xref);
        _execs++;
    }

    void Call::addAnalysis(IReportObject* result) {
        if (result) {
            int xref = (*((std::vector<int>*)_order))[_execs - 1];
            (*((std::map<int, _xref>*)_xrefs))[xref].params.push_back(result);
        }
    }

    bool Call::toJson( Json::Value &root ) const {
        root["target"] = _target;
        root["execs"] = _execs;
        root["name"] = _name ? _name : "";
        root["xrefs"] = Json::Value(Json::arrayValue);

        for (std::map<int, _xref>::iterator it = ((std::map<int, _xref>*)_xrefs)->begin();
            it != ((std::map<int, _xref>*)_xrefs)->end(); ++it) {
                Json::Value xref_json;
                xref_json["addr"] = it->second.ref;
                xref_json["execs"] = it->second.exec;
                xref_json["params"] = Json::Value(Json::arrayValue);

                for (std::vector<IReportObject*>::iterator param_it = it->second.params.begin();
                    param_it != it->second.params.end(); ++param_it) {
                        Json::Value param_json;
                        (*param_it)->toJson( param_json );
                        if (param_json.size() > 0)
                            xref_json["params"].append(param_json);
                }
                root["xrefs"].append(xref_json);
        }

        return true;
    }
}