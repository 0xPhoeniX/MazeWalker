import ctypes
import json

def pre_analyzer(LPSECURITY_ATTRIBUTES_lpMutexAttributes,
                 BOOL_bInitialOwner,
                 LPCTSTR_lpName,
                 **kwargs):

    lpName = ctypes.c_char_p.from_address(LPCTSTR_lpName)
    res = []
    if (lpName and lpName.value):
        result = {'name': 'lpName', 'data': lpName.value}
        res.append(result)
    return json.dumps(res)
