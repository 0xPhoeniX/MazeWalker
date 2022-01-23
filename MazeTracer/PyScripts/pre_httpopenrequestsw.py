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
    res = {}
    if (lpszVerb):
        res['lpszVerb'] = lpszVerb.value
    if (lpszObjectName):
        res['lpszObjectName'] = lpszObjectName.value
    if (lpszReferer):
        res['lpszReferer'] = lpszReferer.value
    return json.dumps(res)
