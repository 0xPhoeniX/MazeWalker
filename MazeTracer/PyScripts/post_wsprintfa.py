import ctypes
import json

def post_analyzer(LPTSTR_lpOut,
                  LPCTSTR_lpFmt,
                  **kwargs):

    lpOut = ctypes.c_char_p.from_address(LPTSTR_lpOut)
    lpFmt = ctypes.c_char_p.from_address(LPCTSTR_lpFmt)
    res = []
    result = {}
    if lpFmt and lpFmt.value:
        result['name'] = 'lpFmt'
        result['data'] = lpFmt.value
        res.append(result)

    result = {}
    if lpOut and lpOut.value:
        result['name'] = 'lpOut'
        result['data'] = lpOut.value
        res.append(result)

    return json.dumps(res)
