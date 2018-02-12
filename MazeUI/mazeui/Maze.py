import idc
import idaapi
import idautils
import ida_ua
import ida_name
import json
import logging
import os
from mazeui.core.helpers import CallAsPushAnalysis

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class Config():
    __metaclass__ = Singleton

    def __init__(self):
        """
        Basic configuration
        """

        # Paths, etc.
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        self.icons_path = self.root_dir + os.sep + 'images' + os.sep
        self.idb_store = "$ com.mazewalker"
        self.log_level = logging.DEBUG

        logger = logging.getLogger('mazeui')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
                '%(levelname)-8s %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(self.log_level)

def IsMazeDataInIDB():
    logger = logging.getLogger(__name__)
    logger.info("Checking for maze data in idb...")
    store = idaapi.netnode(Config().idb_store, 0, True)
    return not (store.getblob(0, 'N') is None)

class Maze(dict):
    __metaclass__ = Singleton
    
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        store = idaapi.netnode(Config().idb_store, 0, True)
        maze = store.getblob(0, 'N')
        if maze is None:
            maze_file = idc.AskFile(0, '*.json', 'Select the Maze...')
            if maze_file:
                with open(maze_file, 'r') as fd:
                    ma_id = int(idc.GetInputFile().split('_')[1], 10)
                    blob = fd.read()
                    maze = json.loads(blob)
                    for i in range(len(maze["mem_areas"])):
                        if maze["mem_areas"][i]["id"] == ma_id:
                            del maze["mem_areas"][0:i]
                            del maze["mem_areas"][1:]
                            break
                    self.update(maze)

                    CallAsPushAnalysis.Analyze(self)
                    self.__mark_bbls()
                    self.__mark_calls()

                    blob = json.dumps(maze)
                    store.setblob(blob, 0, "N")
        else:
            self.update(json.loads(maze))

        self.__create_luts()

    def __create_luts(self):
        self._call_lut = set()

        try:
            for thread in self["mem_areas"][0]['threads']:
                for call in thread["calls"]:
                    if not call['returns']:
                        continue
                    for xref in call["xrefs"]:
                        self._call_lut.add(xref["addr"])
        except KeyError:
            logger = logging.getLogger(__name__)
            logger.warning("The trace data was not loaded correctly!")
            pass

    def __mark_bbls(self):
        for thread in self["mem_areas"][0]['threads']:
            for bbl in thread['bbls']:
                ea = bbl['start']
                for _ in range(bbl['inst']):
                    idaapi.set_item_color(ea, 0x49feaf)
                    ea += idautils.DecodeInstruction(ea).size

    def __mark_calls(self):
        for thread in self["mem_areas"][0]['threads']:
            for call in thread['calls']:

                if not call['returns']:
                    continue

                # generate name for the function
                fname = idc.GetFunctionName(call['target'])
                if len(fname) == 0:
                    if len(call["name"]) > 0:
                        fname = call["name"].encode('ascii')
                    else:
                        fname = "0x%x" % call["target"]
                
                # name all indirect calls
                for xref in call['xrefs']:
                    idc.MakeCode(xref['addr'])
                    op = idc.GetOpType(xref['addr'],0)
                    if op == ida_ua.o_mem:
                        val = idc.GetOperandValue(xref['addr'], 0)
                        vname = idc.get_name(val)
                        if val is not None and val > 0 and len(vname) > 0 and 'dword_' in vname:
                            idc.MakeName(val, fname)
                    elif op == ida_ua.o_reg or op == ida_ua.o_displ:
                        idc.MakeComm(xref['addr'], fname)

    @property
    def threads(self):
        for thread in self["mem_areas"][0]['threads']: 
            fname = idc.GetFunctionName(thread["tfunc"])
            if len(fname) == 0:
                if idc.MakeFunction(thread["tfunc"]) == 0:
                    fname = "0x%x" % thread["tfunc"]
                else:
                    fname = idc.GetFunctionName(thread["tfunc"])
            yield fname, thread["tfunc"], thread["tid"]

    @property
    def bbls(self):
        for thread in self["mem_areas"][0]['threads']:
            for bbl in thread['bbls']:
                if bbl['start'] >= self["mem_areas"][0]['start'] and bbl['start'] <= self["mem_areas"][0]['end']:
                    yield bbl['start'], bbl['end'], bbl['id'], idc.GetFunctionName(bbl['start'])

    def isCall(self, xref, tid):
        if xref in self._call_lut:
            return True
        elif idc.GetMnem(xref) == 'jmp':
            curf = idc.GetFunctionName(xref)
            if curf is not None:
                val = idc.GetOperandValue(xref, 0)
                if val is not None and val > 0:
                    tarf = idc.GetFunctionName(val)
                    if tarf is not None and tarf != curf:
                        self._call_lut.add(xref)
                        for thread in self["mem_areas"][0]['threads']:
                            if thread['tid'] == tid:
                                thread['calls'].append({"execs" : 1, "name" : "", "target" : val,
                                                        "xrefs" : [ { "addr" : xref, "execs" : 1, "params" : []}]})
                        return True

        return False

    def getCallInfo(self, xref_addr, tid):
        result = None
        target = 0
        callee_id = -1
        for thread in self["mem_areas"][0]['threads']:
            if tid == thread['tid']:
                for call in thread['calls']:
                    for xref in call['xrefs']:
                        if xref['addr'] == xref_addr:
                            target = call['target']
                            if len(xref["params"]):
                                if 'count' not in xref:
                                    xref['count'] = 0
                                callee_id = xref['count']
                                xref['count'] += 1
                            if len(call['name']):
                                result = call['name'].encode('ascii')
                            elif 'real_call' in call:
                                result = call['real_call']['name'].encode('ascii')
                                target = call['real_call']['target']
                            else:
                                result = idc.GetFunctionName(target)
                                if len(result) == 0:
                                    opval = idc.GetOperandValue(xref_addr, 0)
                                    if len(idc.get_name(opval)) > 0:
                                        result = idc.get_name(opval)
                                    else:
                                        result = "%x" % target
                            return result, target, callee_id

        return None, None, -1

    def addCallParams(self, target, xref_addr, xrefID, tid):
        if xrefID > -1:
            for thread in self["mem_areas"][0]['threads']:
                if tid == thread['tid']:
                    for call in thread["calls"]:
                        if call["target"] == target:
                            for xref in call["xrefs"]:
                                if xref["addr"] == xref_addr:
                                    cmt = ""
                                    for param in xref['params'][xrefID]:
                                        cmt += (param['name'] + " : " + str(param['data']) + "\n").encode('ascii')
                                    idc.MakeComm(xref_addr, cmt)
                                    break
                            break
                    break