import ctypes
import json
import os
import config
import subprocess
import time


GetProcessId = ctypes.windll.kernel32.GetProcessId


def pre_analyzer(HANDLE_hProcess,
                 LPSECURITY_ATTRIBUTES_lpThreadAttributes,
                 SIZE_T_dwStackSize,
                 LPTHREAD_START_ROUTINE_lpStartAddress,
                 LPVOID_lpParameter,
                 DWORD_dwCreationFlags,
                 LPDWORD_lpThreadId,
                 **kwargs):

    time.sleep(5)
    res = {}
    dwCreationFlags = ctypes.c_int.from_address(DWORD_dwCreationFlags)
    lpStartAddress = ctypes.c_int.from_address(LPTHREAD_START_ROUTINE_lpStartAddress)
    hProcess = ctypes.c_int.from_address(HANDLE_hProcess)

    if (dwCreationFlags):
        res['dwCreationFlags'] = dwCreationFlags.value
    if (lpStartAddress):
        res['lpStartAddress'] = ("0x%x" % lpStartAddress.value)
    if (hProcess and hProcess.value != -1):
        pid = GetProcessId(hProcess.value)
        if os.getpid() != pid and pid > 0:
            res['TargetProcess'] = ("%d" % pid)
            if "pin_dir" in kwargs:
                if pid in config.cache['monitored_processes']:
                    res['DoFollow'] = False
                else:
                    process = subprocess.Popen(kwargs["pin_dir"] +
                                               "/pin.exe -pid " + str(pid) +
                                               " -t " + kwargs["pin_dir"] + "/MazeTracer.dll -cfg " +
                                               kwargs["pin_dir"] + "/config.json -unique_logfile")
                    config.cache['monitored_processes'].append(pid)
                    res['DoFollow'] = True
    return json.dumps(res)
