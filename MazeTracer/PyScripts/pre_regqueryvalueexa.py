import ctypes
import json


def pre_analyzer(HKEY_hKey,
                 LPCTSTR_lpValueName,
                 LPDWORD_lpReserved,
                 LPDWORD_lpType,
                 LPBYTE_lpData,
                 LPDWORD_lpcbData,
                 **kwargs):
    lpValueName = ctypes.c_char_p.from_address(LPCTSTR_lpValueName)
    res = {}
    if lpValueName:
        res['lpValueName'] = lpValueName.value
    return json.dumps(res)
