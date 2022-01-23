import ctypes
import json


def post_analyzer(HANDLE_ProcessHandle,
                  DWORD_ProcInfoClass,
                  PVOID_ProcInfo,
                  ULONG_ProcInfoLength,
                  PULONG_RerLen, **kwargs):
    res = {}
    ProcInfoClass = ctypes.c_int.from_address(DWORD_ProcInfoClass)
    if (ProcInfoClass and ProcInfoClass.value == 0x1F):
        res['ProcInfoClass'] = ("0x%x" % ProcInfoClass.value)
        pProcInfo = ctypes.c_int.from_address(PVOID_ProcInfo)
        if (pProcInfo):
            res['old_pProcInfo'] = ("0x%x" % pProcInfo.value)
            ProcInfo = (ctypes.c_int).from_address(pProcInfo.value)
            res['old_ProcInfo'] = ProcInfo.value
            ProcInfo.value = 1
            res['fixed_ProcInfo'] = ProcInfo.value
    return json.dumps(res)
