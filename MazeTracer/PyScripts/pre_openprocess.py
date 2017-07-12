import ctypes
import json
import os
import subprocess

def pre_analyzer(DWORD_dwDesiredAccess,
                 BOOL_bInheritHandle,
                 DWORD_dwProcessId,
                 **kwargs):

    pid = ctypes.c_int.from_address(DWORD_dwProcessId)
    if (pid and pid.value and os.getpid() != pid.value):
        if "pin_dir" in kwargs and "out_dir" in kwargs:
            process = subprocess.Popen(kwargs["pin_dir"] +
                                       "/pin.exe -unique_logfile -pid " + str(pid.value) +
                                       " -t " + kwargs["pin_dir"] + "/MazeTracer.dll -cfg " +
                                       kwargs["pin_dir"] + "/config.json" +
                                       " -out " + kwargs["out_dir"] + " -unique_logfile")
        res = []
        result = {'name': 'dwProcessId', 'data': pid.value}
        res.append(result)
        return json.dumps(res)
