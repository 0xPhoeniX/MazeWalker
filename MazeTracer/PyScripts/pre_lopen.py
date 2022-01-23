import ctypes
import json


def pre_analyzer(LCPSTR_lpPathName,
                 INT_iReadWrite,
                 **kwargs):
    lpPathName = ctypes.c_char_p.from_address(LCPSTR_lpPathName)
    res = {}
    if (lpPathName):
        res['lpPathName'] = lpPathName.value
    return json.dumps(res)
