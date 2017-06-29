import ctypes
import json

def pre_analyzer(LPCTSTR_lpClassName,
                 LPCTSTR_lpWindowName,
                 **kwargs):

    lpClassName = ctypes.c_char_p.from_address(LPCTSTR_lpClassName)
    lpWindowName = ctypes.c_char_p.from_address(LPCTSTR_lpWindowName)
    res = []
    if (lpClassName and lpClassName.value):
        result = {'name': 'lpClassName', 'data': lpClassName.value}
        res.append(result)
    if (lpWindowName and lpWindowName.value):
        result = {'name': 'lpWindowName', 'data': lpWindowName.value}
        res.append(result)
    return json.dumps(res)
