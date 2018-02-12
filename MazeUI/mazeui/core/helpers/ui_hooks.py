from ida_kernwin import *
from mazeui.core.helpers import CallAsPushAnalysis

hooks = None

class fix_call_handler(action_handler_t):
    """
    This is a handler class.
    Connects the Action with real code
    """
    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        CallAsPushAnalysis.PatchCall(ctx.cur_ea)
        return 1

    def update(self, ctx):
        return AST_ENABLE_FOR_FORM if ctx.form_type == \
            BWN_DISASM else AST_DISABLE_FOR_FORM

class Hooks(UI_Hooks):
    """
    Attach the action to a context menu after
    it has been created
    """
    def finish_populating_tform_popup(self, form, popup):
        # Insert the action once the context menu
        # has been populated.
        # Submenu Others
        if get_tform_type(form) == BWN_DISASM:
            attach_action_to_popup(form, popup, 'fix_call', 'MazeWalker/')

def initialize():

    global hooks

    fix_call_desc = action_desc_t(
        'fix_call',                 # Unique ID
        'Fix push <-> call abuse',  # Action text
        fix_call_handler(),         # Action handler
        None,                       # Optional: shortcut
        'Patch call-push abuse',    # Optional: tooltip (menus, toolbars)
        199                         # Optional: icon (menus, toolbars)
    )

    register_action(fix_call_desc)
    hooks = Hooks()

    if hooks.hook():
        print '[INFO] UI hooks installed successfully'