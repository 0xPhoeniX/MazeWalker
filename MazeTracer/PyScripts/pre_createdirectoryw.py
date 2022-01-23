import ctypes
import json


def pre_analyzer(LPCTSTR_lpPathName,
                 LPSECURITY_ATTRIBUTES_lpSecurityAttributes,
                 **kwargs):

    lpPathName = ctypes.c_wchar_p.from_address(LPCTSTR_lpPathName)
    res = {}
    if (lpPathName):
        res['lpPathName'] = lpPathName.value
    return json.dumps(res)
