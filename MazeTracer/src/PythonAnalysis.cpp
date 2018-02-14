#include <Windows.h>
#include "Python.h"
#include "PythonAnalysis.h"
#include "PythonTypesInternal.h"
#include "cfg.h"


namespace MazeWalker {

    bool PythonBasedAnalysis::ready = false;
    int PythonBasedAnalysis::refs = 0;

    ptrPy_Initialize pPy_Initialize = NULL;
    ptrPy_Finalize pPy_Finalize = NULL;
    ptrPy_IsInitialized pPy_IsInitialized = NULL;
    ptrPyString_FromString pPyString_FromString = NULL;
    ptrPyImport_Import pPyImport_Import = NULL;
    ptrPyModule_GetDict pPyModule_GetDict = NULL;
    ptrPyDict_GetItemString pPyDict_GetItemString = NULL;
    ptrPyCallable_Check pPyCallable_Check = NULL;
    ptrPy_DecRef pPy_DecRef = NULL;
    ptrPySys_GetObject pPySys_GetObject = NULL;
    ptrPyList_Append pPyList_Append = NULL;
    ptrPyErr_Print pPyErr_Print = NULL;
    ptrPyTuple_New pPyTuple_New = NULL;
    ptrPyTuple_SetItem pPyTuple_SetItem = NULL;
    ptrPyDict_New pPyDict_New = NULL;
    ptrPyDict_SetItemString pPyDict_SetItemString = NULL;
    ptrPyObject_Call pPyObject_Call = NULL;
    ptrPyInt_FromLong pPyInt_FromLong = NULL;
    ptrPyObject_Repr pPyObject_Repr = NULL;
    ptrPyString_AsString pPyString_AsString = NULL;
    ptrPyErr_Fetch pPyErr_Fetch = NULL;
    ptr_Py_NoneStruct p_Py_NoneStruct = NULL;

    PythonBasedAnalysis::PythonBasedAnalysis() {
        if (!ready) {
            // If we get this far, the python library should be already loaded
            // by the configuration manager.
            HMODULE lib = GetModuleHandleA("python27.dll");
            if (lib)
            {
                pPy_Initialize = (ptrPy_Initialize)GetProcAddress(lib, "Py_Initialize");
                pPy_Finalize = (ptrPy_Finalize)GetProcAddress(lib, "Py_Finalize");
                pPy_IsInitialized = (ptrPy_IsInitialized)GetProcAddress(lib, "Py_IsInitialized");
                pPyString_FromString = (ptrPyString_FromString)GetProcAddress(lib, "PyString_FromString");
                pPyImport_Import = (ptrPyImport_Import)GetProcAddress(lib, "PyImport_Import");
                pPyModule_GetDict = (ptrPyModule_GetDict)GetProcAddress(lib, "PyModule_GetDict");
                pPyDict_GetItemString = (ptrPyDict_GetItemString)GetProcAddress(lib, "PyDict_GetItemString");
                pPyCallable_Check = (ptrPyCallable_Check)GetProcAddress(lib, "PyCallable_Check");
                pPy_DecRef = (ptrPy_DecRef)GetProcAddress(lib, "Py_DecRef");
                pPySys_GetObject = (ptrPySys_GetObject)GetProcAddress(lib, "PySys_GetObject");
                pPyList_Append = (ptrPyList_Append)GetProcAddress(lib, "PyList_Append");
                pPyErr_Print = (ptrPyErr_Print)GetProcAddress(lib, "PyErr_Print");
                pPyTuple_New = (ptrPyTuple_New)GetProcAddress(lib, "PyTuple_New");
                pPyTuple_SetItem = (ptrPyTuple_SetItem)GetProcAddress(lib, "PyTuple_SetItem");
                pPyDict_New = (ptrPyDict_New)GetProcAddress(lib, "PyDict_New");
                pPyDict_SetItemString = (ptrPyDict_SetItemString)GetProcAddress(lib, "PyDict_SetItemString");
                pPyObject_Call = (ptrPyObject_Call)GetProcAddress(lib, "PyObject_Call");
                pPyInt_FromLong = (ptrPyInt_FromLong)GetProcAddress(lib, "PyInt_FromLong");
                pPyObject_Repr = (ptrPyObject_Repr)GetProcAddress(lib, "PyObject_Repr");
                pPyString_AsString = (ptrPyString_AsString)GetProcAddress(lib, "PyString_AsString");
                pPyErr_Fetch = (ptrPyErr_Fetch)GetProcAddress(lib, "PyErr_Fetch");
                p_Py_NoneStruct = (ptr_Py_NoneStruct)GetProcAddress(lib, "_Py_NoneStruct");

                if (pPy_Initialize &&
                    pPy_Finalize &&
                    pPy_IsInitialized &&
                    pPyString_FromString &&
                    pPyImport_Import &&
                    pPyModule_GetDict &&
                    pPyDict_GetItemString &&
                    pPyCallable_Check &&
                    pPy_DecRef &&
                    pPySys_GetObject &&
                    pPyList_Append &&
                    pPyErr_Print &&
                    pPyTuple_New &&
                    pPyTuple_SetItem &&
                    pPyDict_New &&
                    pPyDict_SetItemString &&
                    pPyObject_Call &&
                    pPyInt_FromLong &&
                    pPyObject_Repr &&
                    pPyErr_Fetch &&
                    p_Py_NoneStruct)
                {
                    pPy_Initialize();

                    if (pPy_IsInitialized() > 0) {
                        PyObject* sysPath = pPySys_GetObject((char*)"path");
                        pPyList_Append(sysPath, pPyString_FromString(CFG::Instance().getScriptsDir()));

                        ready = true;
                    }
                }
            }
        }
        refs++;
    }

    PythonBasedAnalysis::~PythonBasedAnalysis() {
        refs--;
        if (pPy_IsInitialized && pPy_Finalize && refs == 0)
        {
            if (pPy_IsInitialized() > 0)
                pPy_Finalize();
        }
    }
}