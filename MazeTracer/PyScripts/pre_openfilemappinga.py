import ctypes
import json


def pre_analyzer(DWORD_dwDesiredAccess,
                 BOOL_bInheritHandle,
                 LPCTSTR_lpName,
                 **kwargs):

    lpName = ctypes.c_char_p.from_address(LPCTSTR_lpName)
    res = {}
    if (lpName):
        res['lpName'] = lpName.value
    return json.dumps(res)
