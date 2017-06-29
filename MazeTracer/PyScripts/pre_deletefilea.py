import ctypes
import json

def pre_analyzer(LPCTSTR_lpFileName,
                 **kwargs):

    lpFileName = ctypes.c_char_p.from_address(LPCTSTR_lpFileName)
    res = []
    if (lpFileName and lpFileName.value):
        result = {'name': 'lpFileName', 'data': lpFileName.value}
        res.append(result)
    return json.dumps(res)
