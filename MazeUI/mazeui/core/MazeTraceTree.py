from PyQt5 import QtCore
from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem
from mazeui.Maze import Maze
from mazeui.core.helpers.api_tags import get_api_tag
import idautils, idc, idaapi
import logging


class MazeTraceTree(QTreeWidget):
    def __init__(self):
        QTreeWidget.__init__(self)

        self.setColumnCount(8)
        self.setColumnHidden(1, True)   # reference address
        self.setColumnHidden(2, True)   # uuid (obsolete)
        self.setColumnHidden(3, True)   # target address
        self.setColumnHidden(4, True)   # created (y/n)
        self.setColumnHidden(5, True)   # is api
        self.setColumnHidden(6, True)   # tid
        self.setColumnHidden(7, True)   # callee_id
        self.itemClicked.connect(self._onClickItem)
        self._apiGrp = {'All': []}

    def populate(self):
        for fname, addr, tid in Maze().threads:
            root = QTreeWidgetItem(self.invisibleRootItem(),
                                   [fname, hex(int(addr)),
                                    fname, hex(int(addr)),
                                    "n", hex(0), hex(tid),
                                    hex(int(tid))])
            self._add_child(root, addr, tid, 0)

    def _add_child(self, root, ea, tid, depth):
        if ea == 0 or root.text(4) == "y":
            return
        if depth > 80:
            logger = logging.getLogger(__name__)
            logger.info("Maximum recursion depth exceeded!")
            return

        for x in idautils.FuncItems(ea):
            if Maze().isCall(x, tid):
                fname, target, xrefID = Maze().getCallInfo(x, tid)
                if target:
                    current_root = QTreeWidgetItem(root,
                                                   [fname,
                                                    hex(int(x)), "0",
                                                    hex(int(target)),
                                                    "n",
                                                    hex(int(0)),
                                                    hex(int(tid)),
                                                    hex(int(xrefID))])
                    current_root.setFlags(current_root.flags() & ~QtCore.Qt.ItemIsEditable)

                    grp = get_api_tag(fname)
                    if grp not in self._apiGrp:
                        self._apiGrp[grp] = []
                    self._apiGrp[grp].append([root, current_root])
                    self._apiGrp["All"].append(current_root)
                    self._add_child(current_root, target, tid, depth + 1)

        root.setText(4, "y")

    def _onClickItem(self, item):
        xref = int(item.text(1), 16)
        tid = int(item.text(6), 16)
        target = int(item.text(3), 16)
        xrefID = int(item.text(7), 16)
        Maze().addCallParams(target, xref, xrefID, tid)
        idc.Jump(xref)

    def filterByGroup(self, grp):
        if grp == "All":
            for item in self._apiGrp["All"]:
                item.setHidden(False)
        else:
            for item in self._apiGrp["All"]:
                item.setHidden(True)
            for item in self._apiGrp[grp]:
                item[0].setHidden(False)
                item[1].setHidden(False)
                parent = item[0].parent()
                while parent is not None:
                    parent.setHidden(False)
                    parent = parent.parent()

    @property
    def apiGroups(self):
        yield 'All'
        for key in self._apiGrp:
            if ('All' in key) or ('Undefined' in key):
                continue
            yield key
