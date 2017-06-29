#!/usr/bin/python
#
# Name: mazui.py
# Description: This is the MAIN FILE for IDA's MazeWalker plugin
#

import idaapi

from PyQt5 import QtWidgets
from PyQt5.QtGui import QIcon

from mazeui.config import Config
from mazeui.widgets.MazeWalkerWidget import MazeWalkerWidget
from mazeui.core.helpers import idp_hooks

__VERSION__ = 0.1


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
        self.config = Config()
        self.iconp = self.config.icons_path
        self.maze_analysis = None

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setWindowIcon(QIcon(self.iconp + 'user-ironman.png'))

        self.setupWidgets()
        self.setupUI()

    def setupWidgets(self):
        """
        Instantiates all widgets
        """

        # Append to the list every widget you have
        self.Widgets.append(MazeWalkerWidget(self))

        self.setupMazeUIForm()

    def setupMazeUIForm(self):
        """
        Already initialized widgets are arranged in tabs on the main window.
        """
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setTabsClosable(False)

        for widget in self.Widgets:
            self.tabs.addTab(widget, widget.icon, widget.name)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tabs)

        self.parent.setLayout(layout)

    def setupUI(self):
        """
        Manages the IDA UI extensions / modifications.
        """
        idp_hooks.initialize()

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
