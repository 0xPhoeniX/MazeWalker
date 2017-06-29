import ctypes
import json

def pre_analyzer(HKEY_hKey,
                 LPCTSTR_lpValueName,
                 LPDWORD_lpReserved,
                 LPDWORD_lpType,
                 LPBYTE_lpData,
                 LPDWORD_lpcbData,
                 **kwargs):
    lpValueName = ctypes.c_wchar_p.from_address(LPCTSTR_lpValueName)
    res = []
    if (lpValueName and lpValueName.value):
        result = {'name': 'lpValueName', 'data': lpValueName.value}
        res.append(result)

    return json.dumps(res)
