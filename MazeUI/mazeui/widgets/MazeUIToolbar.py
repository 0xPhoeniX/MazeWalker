from PyQt5 import QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, pyqtSignal
from mazeui.Maze import Config
from mazeui.Maze import Maze, IsMazeDataInIDB


class MazeUIToolbar(QtWidgets.QToolBar):

    MazeLoaded = pyqtSignal()
    MazeReload = pyqtSignal()

    def __init__(self):

        QtWidgets.QToolBar.__init__(self)
        self.name = "MazeUITab"
        self.setMovable(False)

        self.addMazeLog = QtWidgets.QAction(
            QIcon(Config().icons_path + 'add-icon.png'),
            '&Open Maze Log',
            self,
            triggered=self._addMazeLog
        )

        self.ReloadMaze = QtWidgets.QAction(
            QIcon(Config().icons_path + 'database-refresh.png'),
            '&Reload',
            self,
            triggered=self._reloadMaze
        )

        self.addAction(self.addMazeLog)
        self.addAction(self.ReloadMaze)


    def OnDataPresence(self):
        if IsMazeDataInIDB():
            self.MazeLoaded.emit()

    def _addMazeLog(self):
        self.MazeLoaded.emit()

    def _reloadMaze(self):
        self.MazeReload.emit()
        