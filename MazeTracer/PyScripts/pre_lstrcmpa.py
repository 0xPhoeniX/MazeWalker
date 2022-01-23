import ctypes
import json


def pre_analyzer(LPCTSTR_lpString1,
                 LPCTSTR_lpString2,
                 **kwargs):

    lpString1 = ctypes.c_char_p.from_address(LPCTSTR_lpString1)
    lpString2 = ctypes.c_char_p.from_address(LPCTSTR_lpString2)
    res = {}
    if (lpString1 and lpString2 and lpString2.value == lpString1.value):
        res['lpString1'] = lpString1.value
        res['lpString2'] = lpString2.value
    return json.dumps(res)
