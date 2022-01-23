import ctypes
import json


def pre_analyzer(LPCVOID_lpBaseAddress,
                 **kwargs):
    res = {}
    BaseAddress = ctypes.c_int.from_address(LPCVOID_lpBaseAddress)
    if (BaseAddress):
        res["BaseAddress"] = ("0x%x" % BaseAddress.value)
    return json.dumps(res)
