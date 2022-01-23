import ctypes
import json


def pre_analyzer(HANDLE_hHandle,
                 DWORD_dwMilliseconds,
                 **kwargs):
    dwMilliseconds = ctypes.c_int.from_address(DWORD_dwMilliseconds)
    res = {}
    if (dwMilliseconds):
        res['old_dwMilliseconds'] = dwMilliseconds.value
        dwMilliseconds.value += 1
        res['new_dwMilliseconds'] = dwMilliseconds.value

    return json.dumps(res)
