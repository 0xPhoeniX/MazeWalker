import ctypes
import json


def pre_analyzer(HKEY_hKey,
                 LPCTSTR_lpSubKey,
                 PHKEY_phkResult,
                 **kwargs):
    lpSubKey = ctypes.c_char_p.from_address(LPCTSTR_lpSubKey)
    hKey = ctypes.c_ulong.from_address(HKEY_hKey)
    res = {}
    if (lpSubKey):
        res['lpSubKey'] = lpSubKey.value

    if hKey:
        if hKey.value == 0x80000000:
            res['hKey'] = 'HKCR'
        elif hKey.value == 0x80000001:
            res['hKey'] = 'HKCU'
        elif hKey.value == 0x80000002:
            res['hKey'] = 'HKLM'
        elif hKey.value == 0x80000003:
            res['hKey'] = 'HKU'
        elif hKey.value == 0x80000005:
            res['hKey'] = 'HKCC'
        else:
            res['hKey'] = '0x%x' % hKey.value
    return json.dumps(res)
