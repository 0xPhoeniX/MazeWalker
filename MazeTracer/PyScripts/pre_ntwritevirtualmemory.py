import ctypes
import json
import os
import config as cfg


def pre_analyzer(HANDLE_ProcessHandle,
                 PVOID_BaseAddress,
                 PVOID_Buffer,
                 ULONG_NumberOfBytesToWrite,
                 PULONG_NumberOfBytesWritten,
                 **kwargs):
    res = []

    ProcessHandle = ctypes.c_int.from_address(HANDLE_ProcessHandle)
    BaseAddress = ctypes.c_int.from_address(PVOID_BaseAddress)
    Buffer = ctypes.c_int.from_address(PVOID_Buffer)
    NumberOfBytesToWrite = ctypes.c_int.from_address(ULONG_NumberOfBytesToWrite)

    if (ProcessHandle and ProcessHandle.value):
        result = {"name": "ProcessHandle", "data": ("0x%x" % ProcessHandle.value)}
        res.append(result)
    
    if (NumberOfBytesToWrite and NumberOfBytesToWrite.value and
            BaseAddress and BaseAddress.value and
            Buffer and Buffer.value):
        result = {"name": "BaseAddress", "data": ("0x%x" % BaseAddress.value)}
        res.append(result)
        result = {"name": "Buffer", "data": ("0x%x" % Buffer.value)}
        res.append(result)
        result = {"name": "NumberOfBytesToWrite", "data": ("0x%x" % NumberOfBytesToWrite.value)}
        res.append(result)
        buf = (ctypes.c_char * NumberOfBytesToWrite.value).from_address(Buffer.value)
        dump_file_name = "\\%d" % os.getpid() +"_0x%x" % BaseAddress.value + "_0x%x.mem" % NumberOfBytesToWrite.value
        if buf.value and "out_dir" in kwargs and dump_file_name not in cfg.cache:
            cfg.cache[dump_file_name] = 1
            with open(kwargs["out_dir"] + dump_file_name, "wb") as f:
                f.write(buf)
    return json.dumps(res)
