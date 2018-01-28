#pragma once
#include "Python.h"


namespace MazeWalker {
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

	extern ptrPy_Initialize pPy_Initialize;
	extern ptrPy_Finalize pPy_Finalize;
	extern ptrPy_IsInitialized pPy_IsInitialized;
	extern ptrPyString_FromString pPyString_FromString;
	extern ptrPyImport_Import pPyImport_Import;
	extern ptrPyModule_GetDict pPyModule_GetDict;
	extern ptrPyDict_GetItemString pPyDict_GetItemString;
	extern ptrPyCallable_Check pPyCallable_Check;
	extern ptrPy_DecRef pPy_DecRef;
	extern ptrPySys_GetObject pPySys_GetObject;
	extern ptrPyList_Append pPyList_Append;
	extern ptrPyErr_Print pPyErr_Print;
	extern ptrPyTuple_New pPyTuple_New;
	extern ptrPyTuple_SetItem pPyTuple_SetItem;
	extern ptrPyDict_New pPyDict_New;
	extern ptrPyDict_SetItemString pPyDict_SetItemString;
	extern ptrPyObject_Call pPyObject_Call;
	extern ptrPyInt_FromLong pPyInt_FromLong;
	extern ptrPyObject_Repr pPyObject_Repr;
	extern ptrPyString_AsString pPyString_AsString;
	extern ptrPyErr_Fetch pPyErr_Fetch;
	extern ptr_Py_NoneStruct p_Py_NoneStruct;
}
