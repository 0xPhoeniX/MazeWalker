import ctypes
import json

def pre_analyzer(HANDLE_hProcess,
                 LPSECURITY_ATTRIBUTES_lpThreadAttributes,
                 SIZE_T_dwStackSize,
                 LPTHREAD_START_ROUTINE_lpStartAddress,
                 LPVOID_lpParameter,
                 DWORD_dwCreationFlags,
                 LPDWORD_lpThreadId,
                 **kwargs):
    res = []
    dwCreationFlags = ctypes.c_int.from_address(DWORD_dwCreationFlags)
    lpStartAddress = ctypes.c_int.from_address(LPTHREAD_START_ROUTINE_lpStartAddress)
    
    if (dwCreationFlags and dwCreationFlags.value):
        result = {"name": "dwCreationFlags", "data": dwCreationFlags.value}
        res.append(result)
    if (lpStartAddress and lpStartAddress.value):
        result = {"name": "lpStartAddress", "data": ("0x%x" % lpStartAddress.value)}
        res.append(result)
    
    return json.dumps(res)
