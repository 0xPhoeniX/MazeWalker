import ctypes
import json

def pre_analyzer(HANDLE_hFile,
                 LPDWORD_lpFileSizeHigh,
                 **kwargs):

    hFile = ctypes.c_int.from_address(HANDLE_hFile)
    res = []
    if (hFile and hFile.value):
        result = {'name': 'hFile', 'data': hFile.value}
        res.append(result)
    return json.dumps(res)
