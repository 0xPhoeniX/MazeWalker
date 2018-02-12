from idaapi import IDP_Hooks

# Rename callbacks are of the same interface as IDP_Hooks' rename method
rename_callbacks = []
idphook = None


class hook_dispatcher(IDP_Hooks):
    def __init__(self):
        IDP_Hooks.__init__(self)

    def rename(self, ea, new_name):
        '''
            Support for pre v7 of IDA
        '''
        global rename_callbacks

        for callback in rename_callbacks:
            callback(ea, new_name)
        return 1

    def ev_rename(self, ea, new_name):
        '''
            Support for post v7 of IDA
        '''
        global rename_callbacks

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
        if idphook.hook():
            print '[INFO] IDP hooks installed successfully'

def register_rename_callback(callback):
    global rename_callbacks
    rename_callbacks.append(callback)
