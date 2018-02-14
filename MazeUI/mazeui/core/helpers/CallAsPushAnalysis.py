import idc
import logging
import idautils
import idaapi
import time


def _getBBLdict(thread):
    result = set()
    for bbl in thread["bbls"]:
        result.add(bbl["start"])
    return result


def Analyze(maze):
    logger = logging.getLogger(__name__)
    for thread in maze["mem_areas"][0]['threads']:
        bblmap = _getBBLdict(thread)
        for call in thread['calls']:
            call["returns"] = True
            for xref in call["xrefs"]:
                cmd = idautils.DecodeInstruction(xref["addr"])
                if cmd is None:
                    logger.info("Can't decode instruction: 0x%x" % xref["addr"])
                    continue
                if ((xref["addr"] + cmd.size) in bblmap) or (xref["addr"] > call['target']):
                    continue
                call["returns"] = False
                PatchCall(xref["addr"])
                # break

def PatchCall(addr):
    '''
    To improve IDA's analysis, the patch converts call abuse
    into push and jmp instructions. The patched data is saved
    as a comment.
    '''
    
    if idc.Byte(addr) == 0xE8:
        logger = logging.getLogger(__name__)
        logger.info("Patching push as call @ %x" % addr)
        data_size = idc.Dword(addr + 1)
        if (data_size) >= 0xfe:
            logger.info("Can't patch: 0x%x" % addr)
            return
        fname = idc.GetFunctionName(addr)
        target = idc.GetOperandValue(addr, 0)
        data_addr = addr + idautils.DecodeInstruction(addr).size
        orig_data = idc.Word(data_addr)
        orig_asm = idc.GetDisasm(addr)
        idc.MakeUnknown(addr, target - addr, idaapi.DOUNK_EXPAND | idaapi.DOUNK_DELNAMES)
        idc.PatchByte(addr, 0x68)
        idc.PatchDword(addr + 1, data_addr)
        idc.PatchByte(data_addr, 0xEB)
        idc.PatchByte(data_addr + 1, data_size - 2)
        # idaapi.analyze_area(addr, data_addr + 2)
        uksize = 0
        if fname != idc.GetFunctionName(target) and fname is not None:
            while uksize < 32:
                x = idautils.DecodeInstruction(target + uksize)
                if x is None:
                    break
                uksize += x.size
            idc.MakeUnknown(target, uksize,  idaapi.DOUNK_EXPAND | idaapi.DOUNK_DELNAMES)
            # idaapi.analyze_area(target, target + uksize + 1)
        idc.MakeComm(addr, "Original: " + orig_asm)
        idc.MakeComm(data_addr, "Original: %x" % orig_data)
