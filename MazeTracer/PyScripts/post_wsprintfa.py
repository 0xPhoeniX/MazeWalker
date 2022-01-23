import ctypes
import json


def post_analyzer(LPTSTR_lpOut,
                  LPCTSTR_lpFmt,
                  **kwargs):

    lpOut = ctypes.c_char_p.from_address(LPTSTR_lpOut)
    lpFmt = ctypes.c_char_p.from_address(LPCTSTR_lpFmt)
    res = {}
    if lpFmt:
        res['lpFmt'] = lpFmt.value

    if lpOut:
        res['lpOut'] = lpOut.value

    return json.dumps(res)
