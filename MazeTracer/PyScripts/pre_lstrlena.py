import ctypes
import json

def pre_analyzer(LPCTSTR_lpString,
                 **kwargs):

    lpString = ctypes.c_char_p.from_address(LPCTSTR_lpString)
    res = []
    if (lpString and lpString.value):
        result = {'name': 'lpString', 'data': lpString.value}
        res.append(result)
    return json.dumps(res)
