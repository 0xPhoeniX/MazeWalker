import ctypes
import json

def pre_analyzer(HKEY_hKey,
                 LPCTSTR_lpSubKey,
                 PHKEY_phkResult,
                 **kwargs):
    lpSubKey = ctypes.c_char_p.from_address(LPCTSTR_lpSubKey)
    hKey = ctypes.c_ulong.from_address(HKEY_hKey)
    res = []
    if (lpSubKey and lpSubKey.value):
        result = {'name': 'lpSubKey', 'data': lpSubKey.value}
        res.append(result)

    if hKey and hKey.value:
        result = {}
        result['name'] = 'hKey'
        if hKey.value == 0x80000000:
            result['data'] = 'HKCR'
        elif hKey.value == 0x80000001:
            result['data'] = 'HKCU'
        elif hKey.value == 0x80000002:
            result['data'] = 'HKLM'
        elif hKey.value == 0x80000003:
            result['data'] = 'HKU'
        elif hKey.value == 0x80000005:
            result['data'] = 'HKCC'
        else:
            result['data'] = '0x%x' % hKey.value
        res.append(result)
    
    return json.dumps(res)
