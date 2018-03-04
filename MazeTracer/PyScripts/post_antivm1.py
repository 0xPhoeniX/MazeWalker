import ctypes
from ctypes import sizeof, c_void_p, c_char, c_long, c_char_p
import json


def replace_string(buffer, string, paterns, new_strs):
    lower_str = string.value.lower()
    for i in range(len(paterns)):
        vm_index = lower_str.find(paterns[i])
        while (vm_index != -1):
            buffer[vm_index:(vm_index+len(paterns[i]))] = new_strs[i]
            vm_index = lower_str.find(paterns[i], vm_index + len(paterns[i]))
    
#SetupDiGetDeviceRegistryPropertyA
def post_analyzer(HDEVINFO_DeviceInfoSet,
                  PSP_DEVINFO_DATA_DeviceInfoData,
                  pProperty,
                  PDWORD_PropertyRegDataType,
                  PBYTE_PropertyBuffer,
                  pPropertyBufferSize,
                  PDWORD_RequiredSize,
                  **kwargs):

    Property = ctypes.c_ulong.from_address(pProperty)
    if (Property.value == 0xC):
        PropertyBufferSize = ctypes.c_ulong.from_address(pPropertyBufferSize)
        if (PropertyBufferSize.value > 0):
            res = []
            pPropertyBuffer = ctypes.c_ulong.from_address(PBYTE_PropertyBuffer)
            PropertyBuffer = ctypes.cast(pPropertyBuffer.value, ctypes.c_char_p)
            buffer = (c_char * PropertyBufferSize.value).from_address(pPropertyBuffer.value)

            res.append({'name': 'PropertyBufferSize', 'data': PropertyBufferSize.value})
            res.append({'name': 'original_PropertyBuffer', 'data': PropertyBuffer.value})
            
            replace_string(buffer, PropertyBuffer, ['vmware', 'virtual'], [b'NewTek', b'Digital'])
            
            res.append({'name': 'fixed_PropertyBuffer', 'data': PropertyBuffer.value})
            
            return json.dumps(res)
