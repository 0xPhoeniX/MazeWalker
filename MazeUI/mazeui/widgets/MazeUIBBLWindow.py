from PyQt5 import QtCore, QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot

from mazeui.Maze import Config
from mazeui.core.MazeBBLTable import MazeBBLTable


class MazeUIBBLWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        """
        Constructor
        """

        QtWidgets.QMainWindow.__init__(self)
        self.name = "Orphaned BBLs"
        self.parent = parent
        self.icon = QIcon(Config().icons_path + 'radar-icon.png')
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        main_layout = QtWidgets.QHBoxLayout()
        self.main_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        main_layout.addWidget(self.main_splitter)

        self.central_widget.setLayout(main_layout)

        layout = QtWidgets.QVBoxLayout()
        self.BBLTableWG = QtWidgets.QWidget()
        self.BBLTableWG.setLayout(layout)

        self.bblTlb = MazeBBLTable()

        layout.addWidget(self.bblTlb)
        self.main_splitter.addWidget(self.BBLTableWG)

    @pyqtSlot()
    def OnDataLoad(self):
        self.bblTlb.populate()

    @pyqtSlot()
    def OnDataReLoad(self):
        self.bblTlb.setRowCount(0)
        self.bblTlb.populate()
