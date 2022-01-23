import ctypes
import json


def pre_analyzer(LPCTSTR_lpFileName,
                 **kwargs):

    lpFileName = ctypes.c_char_p.from_address(LPCTSTR_lpFileName)
    res = {}
    if (lpFileName):
        res['lpFileName'] = lpFileName.value
    return json.dumps(res)
