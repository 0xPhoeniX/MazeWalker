import ctypes
import json

def pre_analyzer(LPCTSTR_lpString1,
                 LPCTSTR_lpString2,
                 **kwargs):

    lpString1 = ctypes.c_char_p.from_address(LPCTSTR_lpString1)
    lpString2 = ctypes.c_char_p.from_address(LPCTSTR_lpString2)
    res = []
    if (lpString1 and lpString1.value and lpString2 and lpString2.value and lpString2.value == lpString1.value):
        result = {'name': 'lpString1', 'data': lpString1.value}
        res.append(result)

        result = {'name': 'lpString2', 'data': lpString2.value}
        res.append(result)
        return json.dumps(res)
    return None
