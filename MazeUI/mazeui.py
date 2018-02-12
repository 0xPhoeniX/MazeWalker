#!/usr/bin/python
#
# Name: mazui.py
# Description: This is the MAIN FILE for IDA's MazeWalker plugin
#

import idaapi

from PyQt5 import QtWidgets
from PyQt5.QtGui import QIcon

from mazeui.Maze import Config
from mazeui.widgets.MazeUITraceWindow import MazeUITraceWindow
from mazeui.widgets.MazeUIBBLWindow import MazeUIBBLWindow
from mazeui.widgets.MazeUIToolbar import MazeUIToolbar
from mazeui.core.helpers import idp_hooks, ui_hooks

__VERSION__ = 0.2


#################################################################
class MazeUIPluginForm(idaapi.PluginForm):
    """
    Setup of core modules and widgets is performed in here.
    """

    def __init__(self):
        """
        Initialization.
        """
        idaapi.PluginForm.__init__(self)
        self.Widgets = []
        self.iconp = Config().icons_path

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setWindowIcon(QIcon(self.iconp + 'user-ironman.png'))

        self.setupWidgets()

        idp_hooks.initialize()
        ui_hooks.initialize()

    def setupWidgets(self):
        """
        Instantiates all widgets
        """

        mazeTree = MazeUITraceWindow(self)
        bblTable = MazeUIBBLWindow(self)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setTabsClosable(False)
        self.toolbar = MazeUIToolbar()

        self.tabs.addTab(mazeTree, mazeTree.icon, mazeTree.name)
        self.tabs.addTab(bblTable, bblTable.icon, bblTable.name)
        self.toolbar.MazeLoaded.connect(mazeTree.OnDataLoad)
        self.toolbar.MazeLoaded.connect(bblTable.OnDataLoad)
        self.toolbar.MazeReload.connect(mazeTree.OnDataReload)
        self.toolbar.MazeReload.connect(bblTable.OnDataReLoad)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.toolbar)
        layout.addWidget(self.tabs)

        self.parent.setLayout(layout)

        self.toolbar.OnDataPresence()


    def Show(self):
        """
        Overload this method to specify form options
        """

        return idaapi.PluginForm.Show(self,
            ":: Maze Walker ::",
            options = (
                idaapi.PluginForm.FORM_CLOSE_LATER |
                idaapi.PluginForm.FORM_RESTORE |
                idaapi.PluginForm.FORM_SAVE |
                idaapi.PluginForm.FORM_CENTERED
                )
            )

    def OnClose(self, form):
        """
        Perform some cleanup here, if necessary
        """
        print "= [*] MazeUIPluginForm closed"
        print "=============================================\n"


#################################################################
class MazeUIPlugin(idaapi.plugin_t):
    """
    This is the skeleton plugin as seen by IDA
    """
    flags = 0
    comment = "MazeWalker Plugin. Speeding up malware analysis."
    help = "It saves time... and headaches."
    wanted_name = "MazeWalker"
    wanted_hotkey = "Ctrl-Alt-F8"

    def init(self):
        self.icon_id = 0
        return idaapi.PLUGIN_PROC

    def run(self, arg = 0):
        f = MazeUIPluginForm()
        f.Show()

    def term(self):
        idaapi.msg("[*] mazeuiPlugin terminated")


#################################################################
def PLUGIN_ENTRY():
    """
    Entry point for IDA
    """
    return MazeUIPlugin()


#################################################################
# Usage as script (through Alt+F7)
#################################################################
def main():

    global MAZEWALKER

    try:
        # There is an instance, reload it
        MAZEWALKER
        MAZEWALKER.OnClose(MAZEWALKER)
        MAZEWALKER = MazeUIPluginForm()

    except:
        # There is no instance yet
        MAZEWALKER = MazeUIPluginForm()

    MAZEWALKER.Show()
    idaapi.set_dock_pos(":: Maze Walker ::", "Functions window", idaapi.DP_INSIDE)


if __name__ == '__main__':
    main()
