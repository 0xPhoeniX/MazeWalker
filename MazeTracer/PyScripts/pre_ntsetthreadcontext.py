import ctypes
from ctypes import *
import json


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [("ControlWord", c_ulong),             # 0x00
                ("StatusWord", c_ulong),              # 0x04
                ("TagWord", c_ulong),                 # 0x08
                ("ErrorOffset", c_ulong),             # 0x0C
                ("ErrorSelector", c_ulong),           # 0x10
                ("DataOffset", c_ulong),              # 0x14
                ("DataSelector", c_ulong),            # 0x18
                ("RegisterArea", c_ubyte * 80),       # 0x1C
                ("Cr0NpxState", c_ulong)              # 0x6C
                ]


class CONTEXT(Structure):
    _fields_ = [("ContextFlags", c_ulong),
                ("Dr0", c_ulong),                     # 0x04
                ("Dr1", c_ulong),                     # 0x08
                ("Dr2", c_ulong),                     # 0x0C
                ("Dr3", c_ulong),                     # 0x10
                ("Dr6", c_ulong),                     # 0x14
                ("Dr7", c_ulong),                     # 0x18
                ("FloatSave", FLOATING_SAVE_AREA),    # 0x1C
                ("SegGs", c_ulong),                   # 0x8C
                ("SegFs", c_ulong),                   # 0x90
                ("SegEs", c_ulong),                   # 0x94
                ("SegDs", c_ulong),                   # 0x98
                ("Edi", c_ulong),                     # 0x9C
                ("Esi", c_ulong),                     # 0xA0
                ("Ebx", c_ulong),                     # 0xA4
                ("Edx", c_ulong),                     # 0xA8
                ("Ecx", c_ulong),                     # 0xAC
                ("Eax", c_ulong),                     # 0xB0
                ("Ebp", c_ulong),                     # 0xB4
                ("Eip", c_ulong),                     # 0xB8
                ("SegCs", c_ulong),                   # 0xBC
                ("EFlags", c_ulong),                  # 0xC0
                ("Esp", c_ulong),                     # 0xC4
                ("SegSs", c_ulong),                   # 0xC8
                ("ExtendedRegisters", c_ubyte * 512)]


def pre_analyzer(HANDLE_hThread, PCONTEXT_lpContext, **kwargs):
    res = {}
    lpContext = ctypes.c_ulong.from_address(PCONTEXT_lpContext)
    if (lpContext):
        Context = CONTEXT.from_address(lpContext.value)
        res["EAX"] = ("0x%x" % Context.Eax)
    return json.dumps(res)
