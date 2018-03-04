import ctypes
import json

def pre_analyzer(HANDLE_hHandle,
                 DWORD_dwMilliseconds,
                 **kwargs):
    dwMilliseconds = ctypes.c_int.from_address(DWORD_dwMilliseconds)
    res = []
    if (dwMilliseconds and dwMilliseconds.value):
        result = {'name': 'old_dwMilliseconds', 'data': dwMilliseconds.value}
        res.append(result)
        dwMilliseconds.value += 1
        result = {'name': 'new_dwMilliseconds', 'data': dwMilliseconds.value}
        res.append(result)
    
    return json.dumps(res)
