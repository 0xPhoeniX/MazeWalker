import ctypes
import json

def pre_analyzer(HINTERNET_hConnect,
                 LPCTSTR_lpszServerName,
                 INTERNET_PORT_nServerPort,
                 LPCTSTR_lpszUsername,
                 LPCTSTR_lpszPassword,
                 DWORD_dwService,
                 DWORD_dwFlags,
                 DWORD_PTR_dwContext,
                 **kwargs):

    lpszServerName = ctypes.c_wchar_p.from_address(LPCTSTR_lpszServerName)
    nServerPort = ctypes.c_long.from_address(INTERNET_PORT_nServerPort)
    lpszUsername = ctypes.c_wchar_p.from_address(LPCTSTR_lpszUsername)
    lpszPassword = ctypes.c_wchar_p.from_address(LPCTSTR_lpszPassword)
    res = []
    if (lpszServerName and lpszServerName.value):
        result = {'name': 'lpszServerName', 'data': lpszServerName.value}
        res.append(result)
    if (nServerPort and nServerPort.value):
        result = {'name': 'nServerPort', 'data': nServerPort.value}
        res.append(result)
    if (lpszUsername and lpszUsername.value):
        result = {'name': 'lpszUsername', 'data': lpszUsername.value}
        res.append(result)
    if (lpszPassword and lpszPassword.value):
        result = {'name': 'lpszPassword', 'data': lpszPassword.value}
        res.append(result)
    return json.dumps(res)
