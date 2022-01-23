import ctypes
import json


def pre_analyzer(LPCTSTR_lpString,
                 **kwargs):

    lpString = ctypes.c_wchar_p.from_address(LPCTSTR_lpString)
    res = {}
    if (lpString):
        res['lpString'] = lpString.value
    return json.dumps(res)
