import ctypes
import json
# import os
# import config as cfg


def pre_analyzer(HANDLE_ProcessHandle,
                 PVOID_BaseAddress,
                 PVOID_Buffer,
                 ULONG_NumberOfBytesToWrite,
                 PULONG_NumberOfBytesWritten,
                 **kwargs):
    res = {}
    ProcessHandle = ctypes.c_int.from_address(HANDLE_ProcessHandle)
    BaseAddress = ctypes.c_int.from_address(PVOID_BaseAddress)
    Buffer = ctypes.c_int.from_address(PVOID_Buffer)
    NumberOfBytesToWrite = ctypes.c_int.from_address(ULONG_NumberOfBytesToWrite)

    if (ProcessHandle):
        res['ProcessHandle'] = ("0x%x" % ProcessHandle.value)
    if (NumberOfBytesToWrite and BaseAddress and Buffer):
        res['BaseAddress'] = ("0x%x" % BaseAddress.value)
        res['Buffer'] = ("0x%x" % Buffer.value)
        res['NumberOfBytesToWrite'] = ("0x%x" % NumberOfBytesToWrite.value)
        # buf = (ctypes.c_char * NumberOfBytesToWrite.value).from_address(Buffer.value)
        # dump_file_name = "\\%d" % os.getpid() +"_0x%x" % BaseAddress.value + "_0x%x.mem" % NumberOfBytesToWrite.value
        # if buf.value and "out_dir" in kwargs and dump_file_name not in cfg.cache:
        #     cfg.cache[dump_file_name] = 1
        #     with open(kwargs["out_dir"] + dump_file_name, "wb") as f:
        #         f.write(buf)
    return json.dumps(res)
