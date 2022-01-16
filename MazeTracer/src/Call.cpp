#include "Call.h"
#include "Image.h"
#include "PEImage.h"
#include "cJSON.h"
#include "PythonInternal.h"
#include <string>
#include <map>
#include <vector>
#include "Logger.h"


namespace MazeWalker {

    class _xref {
    public:
        _xref() : ref(0), exec(0) {}
        _xref(int r, int e) : ref(r), exec(e) { }
        int ref;
        int exec;
        std::vector<int> order;
        std::vector<char*> params;
    };

    Call::Call(int target, int xref, const char* symbol) {
        _target = target;
        _xrefs = new std::map<int, _xref>;
        _params = new std::map<int, char*>;
        _order = new std::vector<int>;
        _execs = 0;
        _name = symbol ? _strdup(symbol) : NULL;
        _image = 0;
        
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

    void Call::Analyze(ApiHook *hook, long* params) {
        PyObject* pName, * pModule, * pDict, * pFunc, * pValue = 0, * pPosArgs;
        PyObject* pKywdArgs, * pResult, * pResultRepr, * ptype, * ptraceback = 0;

        char* err = NULL, * stack = NULL;
        char* json_result = NULL;
        char* result = NULL, *fname = NULL;

        if (hook->pre_parser) {
            pName = pPyString_FromString(hook->pre_parser);
            fname = "pre_analyzer";
        }
        else {
            pName = pPyString_FromString(hook->post_parser);
            fname = "post_analyzer";
        }
        
        pModule = pPyImport_Import(pName);
        if (!pModule) {
            goto error;
        }

        pDict = pPyModule_GetDict(pModule);
        pFunc = pPyDict_GetItemString(pDict, fname);

        if (pPyCallable_Check(pFunc))
        {
            pPosArgs = pPyTuple_New(hook->vars_num);
            pKywdArgs = pPyDict_New();

            for (int i = 0; i < hook->vars_num; i++)
            {
                pValue = pPyInt_FromLong((long)params + (i * sizeof(long)));
                if (!pValue) {
                    goto error;
                }

                if (pPyTuple_SetItem(pPosArgs, i, pValue) != 0) {
                    goto error;
                }
            }

            //pPinDir = pPyString_FromString(script_dir);
            //if (pPinDir)
            //    pPyDict_SetItemString(pKywdArgs, "pin_dir", pPinDir);
            pResult = pPyObject_Call(pFunc, pPosArgs, pKywdArgs);
            if (!pResult) {
                goto error;
            }
            //if (*pResult == p_Py_NoneStruct) {
            //    goto exit;
            //}

            pResultRepr = pPyObject_Repr(pResult);
            result = pPyString_AsString(pResultRepr);
            if (result && strlen(result) > 0) {
                Logger::Write("Analyzer result: %s\n", result);
                json_result = (char*)malloc(strlen(result) + 1);
                if (json_result) {
                    memset(json_result, 0, strlen(result) + 1);
                    memcpy(json_result, result + 1, strlen(result) - 2);
                    int xref = (*((std::vector<int>*)_order))[_execs - 1];
                    (*((std::map<int, _xref>*)_xrefs))[xref].params.push_back(json_result);
                }
            }

            if (_name == NULL) {
                _name = _strdup(hook->name);
            }

            if (_image == NULL) {
                _image = _strdup(hook->lib);
            }

            goto exit;
        }

    error:
        pPyErr_Fetch(&ptype, &pValue, &ptraceback);
        if (pValue != NULL) {
            PyObject* pRepr = pPyObject_Repr(pValue);
            const char* err = pPyString_AsString(pRepr);
            Logger::Write("Call analyzer error: %s\n", err);
            pPy_DecRef(pRepr);
            pPy_DecRef(pValue);
        }
        if (ptraceback != NULL) {
            PyObject* pRepr = pPyObject_Repr(ptraceback);
            pPy_DecRef(pRepr);
            pPy_DecRef(ptraceback);
        }
    exit:
        pPy_DecRef(pModule);
        pPy_DecRef(pName);
    }

    bool Call::toJson( void* root ) const {
        if (root == NULL) return false;

        cJSON_AddNumberToObject((cJSON*)root, "target", _target);
        cJSON_AddNumberToObject((cJSON*)root, "execs", _execs);
        cJSON_AddStringToObject((cJSON*)root, "name", _name ? _name : "");
        cJSON *xrefs = cJSON_AddArrayToObject((cJSON*)root, "xrefs");

        for (std::map<int, _xref>::iterator it = ((std::map<int, _xref>*)_xrefs)->begin();
            it != ((std::map<int, _xref>*)_xrefs)->end(); ++it) {
            cJSON* xref_json = cJSON_CreateObject();

            cJSON_AddNumberToObject(xref_json, "addr", it->second.ref);
            cJSON_AddNumberToObject(xref_json, "exec", it->second.exec);
            cJSON* params = cJSON_AddArrayToObject(xref_json, "params");
            
            for (std::vector<char*>::iterator param_it = it->second.params.begin();
                param_it != it->second.params.end(); ++param_it) {
                
                cJSON* call_res = cJSON_Parse((*param_it));
                cJSON_AddItemToArray(params, call_res);
                free((*param_it));
            }
            cJSON_AddItemToArray(xrefs, xref_json);
        }

        return true;
    }
}