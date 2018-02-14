#include "PythonTypesInternal.h"
#include "ContextAnalyzer.h"
#include "cfg.h"


namespace MazeWalker {

    CallAnalysis::CallAnalysis() : PythonBasedAnalysis() {
        json_result = NULL;
    }

    CallAnalysis::~CallAnalysis() {
        if (json_result) {
            delete[] json_result;
            json_result = NULL;
        }
    }

    bool CallAnalysis::toJson( Json::Value& root ) const {
        Json::CharReaderBuilder builder;
        Json::CharReader *reader = NULL;

        if (json_result && strlen(json_result) > 0) {
            builder["collectComments"] = false;
            reader = builder.newCharReader();
            if (!reader->parse(json_result, json_result + strlen(json_result), &root, false)) {
                // TODO: add logging here
            }
            delete reader;
            return true;
        }

        return false;
    }

    void CallAnalysis::call_analyzer(const char* mod, 
                                      const char* fname, 
                                      short param_num, 
                                      long* params) {
        PyObject *pName, *pModule, *pDict, *pFunc, *pValue = 0, *pPosArgs;
        PyObject *pKywdArgs, *pResult, *pResultRepr, *ptype, *ptraceback = 0;
        PyObject *pOutDir, *pPinDir;

        char* err = NULL, *stack = NULL;
        json_result = NULL;
        char* result = NULL;

        if (PythonBasedAnalysis::ready) {
            pName = pPyString_FromString(mod);
            pModule = pPyImport_Import(pName);
            if (!pModule)
            {
                goto error;
            }

            pDict = pPyModule_GetDict(pModule);
            pFunc = pPyDict_GetItemString(pDict, fname);

            if (pPyCallable_Check(pFunc))
            {
                pPosArgs = pPyTuple_New(param_num);
                pKywdArgs = pPyDict_New();

                for (int i = 0; i < param_num; i++)
                {
                    pValue = pPyInt_FromLong((long)params + (i * sizeof(long)));
                    if (!pValue) {
                        goto error;
                    }

                    if (pPyTuple_SetItem(pPosArgs , i, pValue) != 0) {
                        goto error;
                    }
                }

                pPinDir = pPyString_FromString(CFG::Instance().getRootDir());
                if (pPinDir)
                    pPyDict_SetItemString(pKywdArgs, "pin_dir", pPinDir);
                pResult = pPyObject_Call(pFunc, pPosArgs, pKywdArgs);
                if (!pResult) {
                    goto error;
                }
                if (pResult == (PyObject*)p_Py_NoneStruct) {
                    goto exit;
                }

                pResultRepr = pPyObject_Repr(pResult);
                result = pPyString_AsString(pResultRepr);
                if (result && strlen(result) > 0) {
                    json_result = new char[strlen(result) + 1];
                    memset(json_result, 0, strlen(result) + 1);
                    memcpy(json_result, result + 1, strlen(result) - 2);
                }
                goto exit;
            }

    error:
            pPyErr_Fetch(&ptype, &pValue, &ptraceback);
            if (pValue != NULL) {
                PyObject* pRepr = pPyObject_Repr(pValue);
                pPy_DecRef(pRepr);
            }
            if (ptraceback != NULL) {
                PyObject* pRepr = pPyObject_Repr(ptraceback);
                pPy_DecRef(pRepr);
            }
    exit:
            pPy_DecRef(pModule);
            pPy_DecRef(pName);
        }
    }

    PreCallAnalysis::PreCallAnalysis(int EBP, const Call& call) : CallAnalysis() {
        if (PythonBasedAnalysis::ready) {
            const ApiHook* hook = CFG::Instance().getHook(call.Image(), call.Symbol());
            if (hook) {
                if (hook->pre_parser) {
                    call_analyzer(hook->pre_parser, 
                                  "pre_analyzer", 
                                  hook->vars_num,
                                  (long*)(EBP + 4));
                }
            }
        }
    }

    PostCallAnalysis::PostCallAnalysis(int EBP, const Call& call) : CallAnalysis() {
        if (PythonBasedAnalysis::ready) {
            const ApiHook* hook = CFG::Instance().getHook(call.Image(), call.Symbol());
            if (hook) {
                if (hook->post_parser) {
                    call_analyzer(hook->post_parser, 
                                  "post_analyzer", 
                                  hook->vars_num,
                                  (long*)(EBP + 4));
                }
            }
        }
    }
}