from PyQt5 import QtCore, QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QSplitter, QComboBox

import mazeui.widgets.CustomWidget as cw
from mazeui.core.helpers import idp_hooks
from mazeui.core.MazeAnalysis import Maze
from mazeui.config import Config

import idc
import idaapi
import json

class MazeWalkerWidget(cw.CustomWidget):
    def __init__(self, parent=None):
        """
        Constructor
        """
        idp_hooks.register_rename_callback(self._rename_hook)

        cw.CustomWidget.__init__(self)
        self.name = "Execution Tree"
        self.parent = parent
        self.icon = QIcon(Config().icons_path + 'radar-icon.png')

        # Functionality associated with this widget
        self.ma = parent.maze_analysis

        self._createGui()

    def _createGui(self):

        self._createLayout()
        self._createToolBar('Maze')
        self._createToolBarActions()
        self._createExecutionTree()

        # Output Layout
        self.main_splitter.addWidget(self.ExecutionTreeWG)

    def _createLayout(self):
        """
        This creates the basic layout:
        Buttons & Outputs
        """

        # Layouts (This is a common disposition)
        main_layout = QtWidgets.QHBoxLayout()

        # Output Layout Inner (QSplitter)
        self.main_splitter = QSplitter(QtCore.Qt.Horizontal)

        # Nested layouts
        main_layout.addWidget(self.main_splitter)

        self.central_widget.setLayout(main_layout)

    def _createExecutionTree(self):

        layout = QtWidgets.QVBoxLayout()
        self.ExecutionTreeWG = QtWidgets.QWidget()
        self.ExecutionTreeWG.setLayout(layout)

        self.filter_qbox = QComboBox()
        self.filter_qbox.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.filter_qbox.currentIndexChanged.connect(self._tag_filter)

        self.execution_tree = Maze()
        maze = self._load_maze_from_idb()
        if maze is not None:
            self.execution_tree.init_maze(json.loads(maze)[0], True)
            for tag in self.execution_tree.tags:
                self.filter_qbox.addItem(tag)

        layout.addWidget(self.filter_qbox)
        layout.addWidget(self.execution_tree)

    def _createToolBarActions(self):

        self.addMazeLog = QtWidgets.QAction(
            QIcon(Config().icons_path + 'add-icon.png'),
            '&Open Maze Log',
            self,
            triggered=self._addMazeLog
        )

        self.reloadMazeLog = QtWidgets.QAction(
            QIcon(Config().icons_path + 'arrow-rotate.png'),
            '&Reload Maze Log',
            self,
            triggered=self._ReloadMazeLog
        )

        self.toolbar.addAction(self.addMazeLog)
        self.toolbar.addAction(self.reloadMazeLog)

    def _store_maze_in_idb(self, maze):
        name = "$ com.mazewalker"
        store = idaapi.netnode(name, 0, True)
        store.setblob(maze, 0, "N")

    def _load_maze_from_idb(self):
        name = "$ com.mazewalker"
        store = idaapi.netnode(name, 0, True)
        return store.getblob(0, 'N')

    def _addMazeLog(self):
        maze_file = idc.AskFile(0, '*.json', 'Select the Maze...')
        if maze_file is not None:
            with open(maze_file, 'r') as fd:
                maze = fd.read()
                self._store_maze_in_idb(maze)
                self.filter_qbox.clear()
               
                self.execution_tree.init_maze(json.loads(maze)[0])
                for tag in self.execution_tree.tags:
                    self.filter_qbox.addItem(tag)

    def _ReloadMazeLog(self):
        self.execution_tree.reload_tree()

    def _tag_filter(self, index):
        self.execution_tree.fileter_by_tag(str(self.filter_qbox.itemText(index)))

    def _rename_execution_tree_node(self, root, new_name, old_name):
        if root.text(0) == old_name:
            root.setText(0, new_name)
        count = root.childCount()
        for i in range(count):
            self._rename_execution_tree_node(root.child(i), new_name, old_name)

    def _rename_hook(self, ea, new_name):
        if len(new_name) > 0:
            fname = idc.GetFunctionName(ea)
            if len(fname) == 0:
                fname = "0x%x" % ea
            root = self.execution_tree.invisibleRootItem()
            self._rename_execution_tree_node(root, new_name, fname)
            return 1
