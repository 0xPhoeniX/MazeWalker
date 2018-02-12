from PyQt5 import QtCore, QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QSplitter, QComboBox
from PyQt5.QtCore import pyqtSlot

from mazeui.core.helpers import idp_hooks
from mazeui.core.MazeTraceTree import MazeTraceTree
from mazeui.Maze import Maze, Config

import idc
import idaapi


class MazeUITraceWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        """
        Constructor
        """
        idp_hooks.register_rename_callback(self._rename_hook)

        QtWidgets.QMainWindow.__init__(self)
        self.name = "Execution Tree"
        self.parent = parent
        self.icon = QIcon(Config().icons_path + 'radar-icon.png')
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        # Layout
        main_layout = QtWidgets.QHBoxLayout()
        self.main_splitter = QSplitter(QtCore.Qt.Horizontal)
        main_layout.addWidget(self.main_splitter)
        self.central_widget.setLayout(main_layout)

        # Add Tree Trace
        layout = QtWidgets.QVBoxLayout()
        self.ExecutionTreeWG = QtWidgets.QWidget()
        self.ExecutionTreeWG.setLayout(layout)

        self.execution_tree = MazeTraceTree()

        self.filter_qbox = QComboBox()
        self.filter_qbox.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.filter_qbox.currentIndexChanged.connect(self.filterIndexChanged)

        layout.addWidget(self.filter_qbox)
        layout.addWidget(self.execution_tree)

        self.main_splitter.addWidget(self.ExecutionTreeWG)

    @pyqtSlot()
    def OnDataLoad(self):
        maze = Maze()
        self.execution_tree.populate()
        for grp in self.execution_tree.apiGroups:
            self.filter_qbox.addItem(grp)

    @pyqtSlot()
    def OnDataReload(self):
        self.execution_tree.clear()
        self.execution_tree.populate()

    def filterIndexChanged(self, txt):
        self.execution_tree.filterByGroup(self.filter_qbox.currentText())


    def _rename_tree_node(self, root, new_name, old_name):
        if root.text(0) == old_name:
            root.setText(0, new_name)
        count = root.childCount()
        for i in range(count):
            self._rename_tree_node(root.child(i), new_name, old_name)

    def _rename_hook(self, ea, new_name):
        if len(new_name) > 0:
            fname = idc.GetFunctionName(ea)
            if len(fname) == 0:
                fname = "0x%x" % ea
            root = self.execution_tree.invisibleRootItem()
            self._rename_tree_node(root, new_name, fname)
            return 1
