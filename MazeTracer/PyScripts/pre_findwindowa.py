import ctypes
import json


def pre_analyzer(LPCTSTR_lpClassName,
                 LPCTSTR_lpWindowName,
                 **kwargs):

    lpClassName = ctypes.c_char_p.from_address(LPCTSTR_lpClassName)
    lpWindowName = ctypes.c_char_p.from_address(LPCTSTR_lpWindowName)
    res = {}
    if (lpClassName):
        res['lpClassName'] = lpClassName.value
    if (lpWindowName):
        res['lpWindowName'] = lpWindowName.value
    return json.dumps(res)
