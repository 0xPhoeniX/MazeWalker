#include <Windows.h>
#include "Python.h"
#include "python_support.h"
#include "cfg.h"

typedef void (*ptrPy_Initialize)(void);
typedef void (*ptrPy_Finalize)(void);
typedef int (*ptrPy_IsInitialized)(void);
typedef PyObject* (*ptrPyString_FromString)(const char *v);
typedef PyObject* (*ptrPyImport_Import)(PyObject *name);
typedef PyObject* (*ptrPyModule_GetDict)(PyObject *module);
typedef PyObject* (*ptrPyDict_GetItemString)(PyObject *p, const char *key);
typedef int (*ptrPyCallable_Check)(PyObject *o);
typedef void (*ptrPy_DecRef)(PyObject *o);
typedef PyObject* (*ptrPySys_GetObject)(const char *v);
typedef int (*ptrPyList_Append)(PyObject *list, PyObject *item);
typedef void (*ptrPyErr_Print)();
typedef PyObject* (*ptrPyTuple_New)(Py_ssize_t len);
typedef int (*ptrPyTuple_SetItem)(PyObject *p, Py_ssize_t pos, PyObject *o);
typedef PyObject* (*ptrPyDict_New)();
typedef int (*ptrPyDict_SetItemString)(PyObject *dp, const char *key, PyObject *item);
typedef PyObject* (*ptrPyObject_Call)(PyObject *callable_object, PyObject *args, PyObject *kw);
typedef PyObject* (*ptrPyInt_FromLong)(long v);
typedef PyObject* (*ptr_Py_NoneStruct);
typedef PyObject* (*ptrPyObject_Repr)(PyObject *o);
typedef char* (*ptrPyString_AsString)(PyObject *string);
typedef void (*ptrPyErr_Fetch)(PyObject **ptype, PyObject **pvalue, PyObject **ptraceback);

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

int python_ready = 0;

int load_python(const char* script_base_dir)
{
	HMODULE lib = LoadLibraryA("python27.dll");
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
				pPyList_Append(sysPath, pPyString_FromString(script_base_dir));

				python_ready = 1;
			}
		}
	}

	return python_ready;
}

void unload_python()
{
	if (pPy_IsInitialized && pPy_Finalize)
	{
		if (pPy_IsInitialized() > 0)
			pPy_Finalize();
	}

}

int is_python_ready()
{
	return python_ready;
}

char* call_analyzer(const char* module, const char* func_name, short param_num, long* params, char** err)
{
	PyObject *pName, *pModule, *pDict, *pFunc, *pValue, *pPosArgs, *pKywdArgs, *pResult, *pResultRepr, *ptype, *ptraceback;
	PyObject *pOutDir, *pPinDir;
	char* final_result = NULL;

	*err = NULL;

	if (is_python_ready())
	{
		pName = pPyString_FromString(module);
		pModule = pPyImport_Import(pName);
		if (!pModule)
		{
			goto error;
		}

		pDict = pPyModule_GetDict(pModule);
		pFunc = pPyDict_GetItemString(pDict, func_name);

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

			pOutDir = pPyString_FromString(cfg.output_dir.c_str());
			if (pOutDir)
				pPyDict_SetItemString(pKywdArgs, "out_dir", pOutDir);
			pPinDir = pPyString_FromString(cfg.pin32dir.c_str());
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
			final_result = pPyString_AsString(pResultRepr);
			goto exit;
		}

error:
		pPyErr_Fetch(&ptype, &pValue, &ptraceback);
		*err = pPyString_AsString(pValue);
exit:
		pPy_DecRef(pModule);
		pPy_DecRef(pName);
	}

	return final_result;
}