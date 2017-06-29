import ctypes
import json

def pre_analyzer(HINTERNET_hConnect,
                 LPCTSTR_lpszVerb,
                 LPCTSTR_lpszObjectName,
                 LPCTSTR_lpszVersion,
                 LPCTSTR_lpszReferer,
                 LPCTSTR_lplpszAcceptTypes,
                 DWORD_dwFlags,
                 DWORD_PTR_dwContext,
                 **kwargs):

    lpszVerb = ctypes.c_wchar_p.from_address(LPCTSTR_lpszVerb)
    lpszObjectName = ctypes.c_wchar_p.from_address(LPCTSTR_lpszObjectName)
    lpszReferer = ctypes.c_wchar_p.from_address(LPCTSTR_lpszReferer)
    res = []
    if (lpszVerb and lpszVerb.value):
        result = {'name': 'lpszVerb', 'data': lpszVerb.value}
        res.append(result)
    if (lpszObjectName and lpszObjectName.value):
        result = {'name': 'lpszObjectName', 'data': lpszObjectName.value}
        res.append(result)
    if (lpszReferer and lpszReferer.value):
        result = {'name': 'lpszReferer', 'data': lpszReferer.value}
        res.append(result)
    return json.dumps(res)
