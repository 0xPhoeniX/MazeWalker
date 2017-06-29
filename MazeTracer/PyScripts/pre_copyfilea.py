import ctypes
import json

def pre_analyzer(LPCTSTR_lpExistingFileName,
                 LPCTSTR_lpNewFileName,
                 BOOL_bFailIfExists,
                 **kwargs):

    lpExistingFileName = ctypes.c_char_p.from_address(LPCTSTR_lpExistingFileName)
    lpNewFileName = ctypes.c_char_p.from_address(LPCTSTR_lpNewFileName)
    res = []
    if (lpExistingFileName and lpExistingFileName.value):
        result = {'name': 'lpExistingFileName', 'data': lpExistingFileName.value}
        res.append(result)
    if (lpNewFileName and lpNewFileName.value):
        result = {'name': 'lpNewFileName', 'data': lpNewFileName.value}
        res.append(result)
    return json.dumps(res)
