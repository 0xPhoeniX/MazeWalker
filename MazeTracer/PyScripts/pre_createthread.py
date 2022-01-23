import ctypes
import json


def pre_analyzer(LPSECURITY_ATTRIBUTES_lpThreadAttributes,
                 SIZE_T_dwStackSize,
                 LPTHREAD_START_ROUTINE_lpStartAddress,
                 LPVOID_lpParameter,
                 DWORD_dwCreationFlags,
                 LPDWORD_lpThreadId,
                 **kwargs):
    res = {}
    lpStartAddress = ctypes.c_int.from_address(LPTHREAD_START_ROUTINE_lpStartAddress)
    lpParameter = ctypes.c_int.from_address(LPVOID_lpParameter)

    if (lpStartAddress):
        res['lpStartAddress'] = lpStartAddress.value
    if (lpParameter):
        res['lpParameter'] = lpParameter.value
    return json.dumps(res)
