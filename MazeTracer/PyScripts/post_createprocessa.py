from ctypes import *
from ctypes.wintypes import DWORD, HANDLE
import json
import config


class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD)]


def post_analyzer(LPCTSTR_lpApplicationName,
                  LPTSTR_lpCommandLine,
                  LPSECURITY_ATTRIBUTES_lpProcessAttributes,
                  LPSECURITY_ATTRIBUTES_lpThreadAttributes,
                  BOOL_bInheritHandles,
                  DWORD_dwCreationFlags,
                  LPVOID_lpEnvironment,
                  LPCTSTR_lpCurrentDirectory,
                  LPSTARTUPINFO_lpStartupInfo,
                  LPPROCESS_INFORMATION_lpProcessInformation,
                  **kwargs):

    plpProcessInformation = c_int.from_address(LPPROCESS_INFORMATION_lpProcessInformation)
    res = {}
    if plpProcessInformation:
        lpProcessInformation = PROCESS_INFORMATION.from_address(plpProcessInformation.value)
        if lpProcessInformation and lpProcessInformation.dwProcessId > 0:
            config.cache['monitored_processes'].append(lpProcessInformation.dwProcessId)
            res['dwProcessId'] = lpProcessInformation.dwProcessId
    return json.dumps(res)
