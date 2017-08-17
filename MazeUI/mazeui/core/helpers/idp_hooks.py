from idaapi import *
from idc import *
from idautils import *

rename_callbacks = []
idphook = None


class hook_dispatcher(IDP_Hooks):

    def rename(self, ea, new_name):
        global rename_callbacks
        """
        The kernel has renamed a byte
        @param ea: Address
        @param new_name: The new name
        @param local_name: Is local name
        @return: Ignored
        """

        for callback in rename_callbacks:
            callback(ea, new_name)
        return 1

def initialize():
    global idphook
    try:
        idp_hook_stat = "un"
        idphook
        idphook.unhook()
        idphook = None
    except:
        idp_hook_stat = ""
        idphook = hook_dispatcher()
        idphook.hook()

def register_rename_callback(callback):
    global renamed_callbacks
    rename_callbacks.append(callback)
