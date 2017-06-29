import ctypes
import json

def pre_analyzer(HWND_hWnd,
                 LPCTSTR_lpString,
                 **kwargs):

    hWnd = ctypes.c_int.from_address(HWND_hWnd)
    lpString = ctypes.c_char_p.from_address(LPCTSTR_lpString)
    res = []
    if (hWnd and hWnd.value):
        result = {'name': 'hWnd', 'data': hWnd.value}
        res.append(result)
    if (lpString and lpString.value):
        result = {'name': 'lpString', 'data': lpString.value}
        res.append(result)
    return json.dumps(res)
