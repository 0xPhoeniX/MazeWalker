from mazeui.core.helpers.api_tags import get_api_tag
from mazeui.core.helpers.utils import PatchCall
import idc
import idaapi
import idautils
import ida_ua
from PyQt5 import QtCore
from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem

class Maze(QTreeWidget):
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
        self.itemClicked.connect(self._execution_tree_onClickItem)

        # memory dump index
        self.index = int(idc.GetInputFile().split('_')[0], 10)

        self._maze = None
        self._tags = {"All": []}

    def init_maze(self, maze, from_idb=False):
        assert isinstance(maze, (dict))
        self.clear()
        self._tags = {"All": []}
        self._maze = maze
        self.dup_apis = set()
        self._from_idb = from_idb
        self.mark_bbls(self.index)
        self.mark_calls(self.index)
        self.mark_threads(self.index)

    def reload_tree(self):
        self.clear()
        self._tags = {"All": []}
        self.mark_threads(self.index)

    def fileter_by_tag(self, tag):
        if tag == "All":
            for item in self._tags["All"]:
                item.setHidden(False)
        else:
            for item in self._tags["All"]:
                item.setHidden(True)
            for item in self._tags[tag]:
                item[0].setHidden(False)
                item[1].setHidden(False)
                parent = item[0].parent()
                while parent is not None:
                    parent.setHidden(False)
                    parent = parent.parent()

    @property
    def tags(self):
        yield 'All'
        for key in self._tags.keys():
            if key != 'All':
                yield key

    def mark_bbls(self, mem_area_id):
        if not self._from_idb:
            for tid in self._maze['process']['mem_areas'][mem_area_id]['tids']:
                for thread in self._maze['process']['threads']:
                    if tid == thread['tid']:
                        for bbl in thread['bbls']:
                            ea = bbl['start']
                            for _ in range(bbl['end'] - bbl['start']):
                                idaapi.set_item_color(ea, 0x49feaf)
                                ea += 1

    def mark_calls(self, mem_area_id):
        if not self._from_idb:
            for tid in self._maze['process']['mem_areas'][mem_area_id]['tids']:
                for thread in self._maze['process']['threads']:
                    if tid == thread['tid']:
                        for call in thread['calls']:
                            if 'name' in call:
                                fname = call['name'].encode('ascii')
                                if len(call['callees']) == 1:
                                    ref = call['callees'][0]['addr']
                                    # propagate symbols into calls which wrap jmps
                                    if idc.GetMnem(ref) == "jmp":
                                        while fname in self.dup_apis:
                                            fname += "_"
                                        self.dup_apis.add(fname)
                                        idc.MakeName(idc.GetOperandValue(ref, 0), fname)
                                        for wrap_call in thread['calls']:
                                            if wrap_call["target"] == ref:
                                                wrap_call['real_call'] = call
                                        continue
                            else:
                                fname = idc.GetFunctionName(call['target'])
                                if len(fname) == 0:
                                    fname = "0x%x" % call['target']
                                elif 'sub_' in fname:
                                    fname = None

                            for callee in call['callees']:
                                op = idc.GetOpType(callee['addr'],0)
                                if op == ida_ua.o_mem and fname is not None:
                                    val = idc.GetOperandValue(callee['addr'], 0)
                                    if val is not None and val > 0:
                                        idc.MakeName(val, fname)
                                elif op == ida_ua.o_reg:
                                    idc.MakeComm(callee['addr'], fname)
                                elif op == ida_ua.o_near and call['suspect']:
                                    data_size = idc.Dword(callee['addr'] + 1)
                                    if data_size < 2:
                                        print "[INFO] Not enough place for patching."
                                    elif data_size <= 0xFF:
                                        PatchCall(callee['addr'])
                                    else:
                                        print "[INFO] Manual check suspect call: %x" % (callee['addr'])

    def mark_threads(self, mem_area_id):
        def get_tfuncs():
            entry = self._maze['process']['mem_areas'][mem_area_id]['entry']
            yield entry

            ma_start = self._maze['process']['mem_areas'][mem_area_id]['start']
            ma_end = self._maze['process']['mem_areas'][mem_area_id]['end']
            for tid in self._maze['process']['mem_areas'][mem_area_id]['tids']:
                for thread in self._maze['process']['threads']:
                    if thread['tid'] == tid:
                        if thread['tfunc'] != entry and thread['tfunc'] > ma_start and thread['tfunc'] < ma_end:
                            yield thread['tfunc']
                            break

        tid = 0
        for tfunc in get_tfuncs():
            fname = idc.GetFunctionName(tfunc)
            if len(fname) == 0:
                if idc.MakeFunction(tfunc) == 0:
                    fname = "0x%x" % tfunc
                else:
                    fname = idc.GetFunctionName(tfunc)
            root = QTreeWidgetItem(self.invisibleRootItem(),
                                   [fname, hex(int(tfunc)),
                                    fname, hex(int(tfunc)),
                                    "n", hex(0), hex(tid),
                                    hex(int(self._maze['process']['mem_areas'][mem_area_id]['tids'][tid]))])
            self._add_child_subs(root, tfunc, self._maze['process']['mem_areas'][mem_area_id]['tids'][tid])
            tid += 1

    def _execution_tree_onClickItem(self, item):
        address = int(item.text(1), 16)
        is_api = int(item.text(5), 16)
        tid = int(item.text(6), 16)
        target = int(item.text(3), 16)
        callee_id = int(item.text(7), 16)
        if is_api > 0:
            for thread in self._maze['process']['threads']:
                if tid == thread['tid']:
                    for i in range(len(thread['api_parameters'])):
                        if thread['api_parameters'][i]['target'] == target and thread['api_parameters'][i]['id'] == callee_id:
                            if thread['api_parameters'][i]['xref'] == (address + idc.ItemSize(address)):
                                if 'parameters' in thread['api_parameters'][i]:
                                    cmt = item.text(0).encode('ascii') + "\n"
                                    for param in thread['api_parameters'][i]['parameters']:
                                        cmt += (param['name'] + " : " + str(param['data']) + "\n").encode('ascii')
                                    idc.MakeComm(address, cmt)
                                    break
        idc.Jump(address)

    def _valid_call(self, ref_addr, target_addr):
        if ref_addr and target_addr:
            ref_func = idc.GetFunctionName(ref_addr)
            target_func = idc.GetFunctionName(target_addr)
            if ref_func == target_func:
                return False

        return True

    def _logged_call(self, ref_addr, tid):
        result = None
        is_api = 0
        target = 0
        callee_id = -1
        for thread in self._maze['process']['threads']:
            if tid == thread['tid']:
                for call in thread['calls']:
                    for callee in call['callees']:
                        if callee['addr'] == ref_addr:
                            if 'count' not in callee:
                                callee['count'] = 0
                            try:
                                callee_id = callee['ids'][callee['count']]
                                if 'real_call' in call:
                                    callee_id += 1
                            except:
                                continue
                            target = call['target']
                            if 'name' in call:
                                result = call['name'].encode('ascii')
                                is_api = 1
                            elif 'real_call' in call:
                                is_api = 1
                                result = call['real_call']['name'].encode('ascii')
                                target = call['real_call']['target']
                            else:
                                result = idc.GetFunctionName(target)
                                if len(result) == 0:
                                    result = "[0x%x]" % target
                            callee['count'] += 1
                            return result, target, is_api, callee_id

        return None, None, 0, -1

    def _add_child_subs(self, root, ea, tid):
        if ea == 0 or root.text(4) == "y":
            return

        for x in idautils.FuncItems(ea):
            if idaapi.is_call_insn(x):
                fname, target_addr, is_api, callee_id = self._logged_call(x, tid)
                if self._valid_call(x, target_addr) and fname:
                    current_root = QTreeWidgetItem(root,
                                                   [fname,
                                                    hex(int(x)), "0",
                                                    hex(int(target_addr)),
                                                    "n",
                                                    hex(int(is_api)),
                                                    hex(int(tid)),
                                                    hex(int(callee_id))])
                    current_root.setFlags(current_root.flags() & ~QtCore.Qt.ItemIsEditable)
                    try:
                        self._tags[get_api_tag(fname)].append([root, current_root])
                    except KeyError:
                        self._tags[get_api_tag(fname)] = [[root, current_root]]
                    self._tags["All"].append(current_root)
                    self._add_child_subs(current_root, target_addr, tid)
        root.setText(4, "y")
