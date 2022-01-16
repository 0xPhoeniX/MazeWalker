#include "PythonInternal.h"
#include "Windows.h"
#include "Logger.h"


namespace MazeWalker {
    bool python_ready = false;

    ptrPy_Initialize pPy_Initialize;
    ptrPy_Finalize pPy_Finalize;
    ptrPy_IsInitialized pPy_IsInitialized;
    ptrPyString_FromString pPyString_FromString;
    ptrPyImport_Import pPyImport_Import;
    ptrPyModule_GetDict pPyModule_GetDict;
    ptrPyDict_GetItemString pPyDict_GetItemString;
    ptrPyCallable_Check pPyCallable_Check;
    ptrPy_DecRef pPy_DecRef;
    ptrPySys_GetObject pPySys_GetObject;
    ptrPyList_Append pPyList_Append;
    ptrPyErr_Print pPyErr_Print;
    ptrPyTuple_New pPyTuple_New;
    ptrPyTuple_SetItem pPyTuple_SetItem;
    ptrPyDict_New pPyDict_New;
    ptrPyDict_SetItemString pPyDict_SetItemString;
    ptrPyObject_Call pPyObject_Call;
    ptrPyInt_FromLong pPyInt_FromLong;
    ptrPyObject_Repr pPyObject_Repr;
    ptrPyString_AsString pPyString_AsString;
    ptrPyErr_Fetch pPyErr_Fetch;
    ptr_Py_NoneStruct p_Py_NoneStruct;

	bool LoadPython() {
        if (python_ready == false) {
            HMODULE hndl = LoadLibraryA("C:\\Users\\JohnDoe\\Downloads\\MazeWalker\\MazeTracer\\Pin\\ia32\\bin\\python27.dll");
            if (hndl) {
                Logger::Write("Python DLL found: 0x%x\nLoading API\n", (DWORD)hndl);
                pPy_Initialize = (ptrPy_Initialize)GetProcAddress(hndl, "Py_Initialize");
                pPy_Finalize = (ptrPy_Finalize)GetProcAddress(hndl, "Py_Finalize");
                pPy_IsInitialized = (ptrPy_IsInitialized)GetProcAddress(hndl, "Py_IsInitialized");
                pPyString_FromString = (ptrPyString_FromString)GetProcAddress(hndl, "PyString_FromString");
                pPyImport_Import = (ptrPyImport_Import)GetProcAddress(hndl, "PyImport_Import");
                pPyModule_GetDict = (ptrPyModule_GetDict)GetProcAddress(hndl, "PyModule_GetDict");
                pPyDict_GetItemString = (ptrPyDict_GetItemString)GetProcAddress(hndl, "PyDict_GetItemString");
                pPyCallable_Check = (ptrPyCallable_Check)GetProcAddress(hndl, "PyCallable_Check");
                pPy_DecRef = (ptrPy_DecRef)GetProcAddress(hndl, "Py_DecRef");
                pPySys_GetObject = (ptrPySys_GetObject)GetProcAddress(hndl, "PySys_GetObject");
                pPyList_Append = (ptrPyList_Append)GetProcAddress(hndl, "PyList_Append");
                pPyErr_Print = (ptrPyErr_Print)GetProcAddress(hndl, "PyErr_Print");
                pPyTuple_New = (ptrPyTuple_New)GetProcAddress(hndl, "PyTuple_New");
                pPyTuple_SetItem = (ptrPyTuple_SetItem)GetProcAddress(hndl, "PyTuple_SetItem");
                pPyDict_New = (ptrPyDict_New)GetProcAddress(hndl, "PyDict_New");
                pPyDict_SetItemString = (ptrPyDict_SetItemString)GetProcAddress(hndl, "PyDict_SetItemString");
                pPyObject_Call = (ptrPyObject_Call)GetProcAddress(hndl, "PyObject_Call");
                pPyInt_FromLong = (ptrPyInt_FromLong)GetProcAddress(hndl, "PyInt_FromLong");
                pPyObject_Repr = (ptrPyObject_Repr)GetProcAddress(hndl, "PyObject_Repr");
                pPyString_AsString = (ptrPyString_AsString)GetProcAddress(hndl, "PyString_AsString");
                pPyErr_Fetch = (ptrPyErr_Fetch)GetProcAddress(hndl, "PyErr_Fetch");
                //p_Py_NoneStruct = (ptr_Py_NoneStruct)GetProcAddress(hndl, "_Py_NoneStruct");

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
                    pPyErr_Fetch) {
                    python_ready = true;
                }
            }
            else {
                Logger::Write("Python did not load\n");
            }
        }

        return python_ready;
	}
}