import idc

def PatchCall(addr):
    '''
    For improving IDA's analysis the patch converts coll abuse
    into push and jmp instructions. The patched data is saved
    as comment.
    '''
    
    if idc.Byte(addr) == 0xE8:
        print "[INFO] Patching push as call @ %x" % addr
        data_size = idc.Dword(addr + 1)
        data_addr = addr + 5
        orig_data = idc.Word(data_addr)
        orig_asm = idc.GetDisasm(addr)
        idc.PatchByte(addr, 0x68)
        idc.PatchDword(addr + 1, data_addr)
        idc.PatchByte(data_addr, 0xEB)
        idc.PatchByte(data_addr + 1, data_size - 2)
        idc.MakeUnknown(data_addr + 2, data_size - 2, 0)
        idc.MakeArray(data_addr + 2, data_size - 2)
        idc.MakeComm(addr, "Original: " + orig_asm)
        idc.MakeComm(data_addr, "Original: %x" % orig_data)
        idc.MakeCode(data_addr)
