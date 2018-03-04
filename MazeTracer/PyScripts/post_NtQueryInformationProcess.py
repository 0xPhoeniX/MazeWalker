import ctypes
from ctypes import *
import json


def post_analyzer(HANDLE_ProcessHandle,
                 DWORD_ProcInfoClass,
                 PVOID_ProcInfo,
                 ULONG_ProcInfoLength,
                 PULONG_RerLen, **kwargs):
    res = []
    result = {}
    ProcInfoClass = ctypes.c_int.from_address(DWORD_ProcInfoClass)

    if (ProcInfoClass and ProcInfoClass.value and ProcInfoClass.value == 0x1F):
        result = {"name": "ProcInfoClass", "data": ("0x%x" % ProcInfoClass.value)}
        res.append(result)
        pProcInfo = ctypes.c_int.from_address(PVOID_ProcInfo)
        if (pProcInfo and pProcInfo.value):
            result = {"name": "old_pProcInfo", "data": ("0x%x" % pProcInfo.value)}
            res.append(result)
            ProcInfo = (ctypes.c_int).from_address(pProcInfo.value)
            result = {"name": "old_ProcInfo", "data": ProcInfo.value}
            res.append(result)
            ProcInfo.value = 1
            result = {"name": "fixed_ProcInfo", "data": ProcInfo.value}
            res.append(result)
    return json.dumps(res)
