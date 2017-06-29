import ctypes
import json

def pre_analyzer(LPCTSTR_lpPathName,
                 LPSECURITY_ATTRIBUTES_lpSecurityAttributes,
                 **kwargs):

    lpPathName = ctypes.c_char_p.from_address(LPCTSTR_lpPathName)
    res = []
    if (lpPathName and lpPathName.value):
        result = {'name': 'lpPathName', 'data': lpPathName.value}
        res.append(result)
    return json.dumps(res)
