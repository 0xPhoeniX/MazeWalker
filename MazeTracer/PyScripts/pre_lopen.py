import ctypes
import json

def pre_analyzer(LCPSTR_lpPathName,
                 INT_iReadWrite,
                 **kwargs):
    lpPathName = ctypes.c_char_p.from_address(LCPSTR_lpPathName)
    res = []
    if (lpPathName and lpPathName.value):
        result = {'name': 'lpPathName', 'data': lpPathName.value}
        res.append(result)
    
    return json.dumps(res)
