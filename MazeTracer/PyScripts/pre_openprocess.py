import ctypes
import json
import os
import subprocess
import config


def pre_analyzer(DWORD_dwDesiredAccess,
                 BOOL_bInheritHandle,
                 DWORD_dwProcessId,
                 **kwargs):

    pid = ctypes.c_int.from_address(DWORD_dwProcessId)
    if (pid and pid.value and os.getpid() != pid.value):
        if "pin_dir" in kwargs:
            if pid.value not in config.cache['monitored_processes']:
                process = subprocess.Popen(kwargs["pin_dir"] +
                                           "/pin.exe -pid " + str(pid.value) +
                                           " -t " + kwargs["pin_dir"] + "/MazeTracer.dll -cfg " +
                                           kwargs["pin_dir"] + "/config.json -unique_logfile")
                config.cache['monitored_processes'].append(pid.value)
        res = []
        result = {'name': 'dwProcessId', 'data': pid.value}
        res.append(result)
        return json.dumps(res)
