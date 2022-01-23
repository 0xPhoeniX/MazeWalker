import ctypes
import json


def pre_analyzer(LPCTSTR_lpExistingFileName,
                 LPCTSTR_lpNewFileName,
                 BOOL_bFailIfExists,
                 **kwargs):

    lpExistingFileName = ctypes.c_char_p.from_address(LPCTSTR_lpExistingFileName)
    lpNewFileName = ctypes.c_char_p.from_address(LPCTSTR_lpNewFileName)
    res = {}
    if (lpExistingFileName):
        res['lpExistingFileName'] = lpExistingFileName.value
    if (lpNewFileName):
        res['lpNewFileName'] = lpNewFileName.value
    return json.dumps(res)
