# Name: CustomWidget.py
# Description: This is a "super" widget. All others must subclass it
#

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QSplitter

#################################################################
class CustomWidget(QtWidgets.QMainWindow):

    def __init__(self):
        """
        Constructor
        """
        QtWidgets.QMainWindow.__init__(self)
        self.name = "Custom widget"
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

    def _createGui(self):
        """
        Subclasses must override this
        depending on the elements they want to add
        and add them to the corresponding layouts.
        """
        raise NotImplementedError

    def _createToolBar(self, name):
        """
        Subclasses need to define the
        specific Actions
        """
        self.toolbar = self.addToolBar(name)
        self.toolbar.setMovable(False)

    def _createLayout(self):
        """
        This creates the basic layout:
        Buttons & Outputs
        """

        # Layouts (This is a common disposition)
        main_layout = QtWidgets.QVBoxLayout()
        self.button_layout = QtWidgets.QHBoxLayout()
        output_layout = QtWidgets.QVBoxLayout()

        # You will need to create your buttons
        # and add them to your layout like this:
        # self.button_layout.addWidget(button_1)

        # Output Layout Inner (QSplitter)
        # Add as many widgets as you please
        # They will be ordered vertically and
        # be resizable by the user
        # self.splitter.addWidget(self.table_label)
        # self.splitter.addWidget(...)
        self.splitter = QSplitter(QtCore.Qt.Vertical)

        # Nested layouts
        main_layout.addLayout(self.button_layout)
        output_layout.addWidget(self.splitter)
        main_layout.addLayout(output_layout)
        self.central_widget.setLayout(main_layout)
