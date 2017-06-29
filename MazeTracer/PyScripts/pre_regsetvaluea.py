import ctypes
import json

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_DWORD_LITTLE_ENDIAN = 4
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10

def pre_analyzer(HKEY_hKey,
                 LPCTSTR_lpValueName,
                 DWORD_Reserved,
                 DWORD_dwType,
                 BYTE_plpData,
                 DWORD_cbData,
                 **kwargs):
    lpValueName = ctypes.c_char_p.from_address(LPCTSTR_lpValueName)
    dwType = ctypes.c_int.from_address(DWORD_dwType)
    res = []
    if (lpValueName and lpValueName.value):
        result = {'name': 'lpValueName', 'data': lpValueName.value}
        res.append(result)

    if dwType and dwType.value:
        if dwType.value == REG_SZ:
            lpData = ctypes.c_char_p.from_address(BYTE_plpData)
            result = {'name': 'lpData', 'data': lpData.value}
            res.append(result)

    return json.dumps(res)
