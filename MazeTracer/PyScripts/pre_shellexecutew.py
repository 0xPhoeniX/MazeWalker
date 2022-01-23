import ctypes
import json


def pre_analyzer(HWND_hwnd,
                 LPCWSTR_lpOperation,
                 LPCWSTR_lpFile,
                 LPCWSTR_lpParameters,
                 LPCWSTR_lpDirectory,
                 INT_nShowCmd,
                 **kwargs):

    File = ctypes.c_wchar_p.from_address(LPCWSTR_lpFile)
    res = {}
    if (File):
        res['lpFile'] = File.value
    return json.dumps(res)
