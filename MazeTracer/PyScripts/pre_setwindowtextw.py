import ctypes
import json


def pre_analyzer(HWND_hWnd,
                 LPCTSTR_lpString,
                 **kwargs):

    hWnd = ctypes.c_int.from_address(HWND_hWnd)
    lpString = ctypes.c_wchar_p.from_address(LPCTSTR_lpString)
    res = {}
    if (hWnd):
        res['hWnd'] = hWnd.value
    if (lpString):
        res['lpString'] = lpString.value
    return json.dumps(res)
