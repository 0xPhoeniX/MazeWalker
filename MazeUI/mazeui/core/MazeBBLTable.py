from PyQt5 import QtWidgets
import idc
from mazeui.Maze import Maze


class MazeBBLTable(QtWidgets.QTableWidget):

    def __init__(self):

        QtWidgets.QTableWidget.__init__(self)
        self.setColumnCount(3)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.cellClicked.connect(self._OnClick)

    def populate(self):
        for s, e, id, name in Maze().bbls:
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QtWidgets.QTableWidgetItem(str(id)))
            self.setItem(row, 1, QtWidgets.QTableWidgetItem(hex(s)))
            self.setItem(row, 2, QtWidgets.QTableWidgetItem(name))

    def _OnClick(self, row, column):
        if column == 1:
            item = self.item(row, column)
            address = int(item.text(), 16)
            idc.Jump(address)
