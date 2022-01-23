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
    res = {}
    if (lpszServerName):
        res['lpszServerName'] = lpszServerName.value
    if (nServerPort):
        res['nServerPort'] = nServerPort.value
    if (lpszUsername):
        res['lpszUsername'] = lpszUsername.value
    if (lpszPassword):
        res['lpszPassword'] = lpszPassword.value
    return json.dumps(res)
