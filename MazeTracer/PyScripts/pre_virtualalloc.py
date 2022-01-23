import ctypes
import json


def pre_analyzer(LPVOID_lpBaseAddress,
                 DWORD_size,
                 DWORD_AllocType,
                 DWORD_Protect,
                 **kwargs):
    res = {}
    BaseAddress = ctypes.c_int.from_address(LPVOID_lpBaseAddress)
    Size = ctypes.c_int.from_address(DWORD_size)
    if (BaseAddress):
        res["BaseAddress"] = ("0x%x" % BaseAddress.value)
    if (Size):
        res["Size"] = ("0x%x" % Size.value)
    return json.dumps(res)
