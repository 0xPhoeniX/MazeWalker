import ctypes
import json


def replace_string(buffer, string, paterns, new_strs):
    lower_str = string.value.lower()
    for i in range(len(paterns)):
        vm_index = lower_str.find(paterns[i])
        while (vm_index != -1):
            buffer[vm_index:(vm_index + len(paterns[i]))] = new_strs[i]
            vm_index = lower_str.find(paterns[i], vm_index + len(paterns[i]))


# SetupDiGetDeviceRegistryPropertyA
def post_analyzer(HDEVINFO_DeviceInfoSet,
                  PSP_DEVINFO_DATA_DeviceInfoData,
                  pProperty,
                  PDWORD_PropertyRegDataType,
                  PBYTE_PropertyBuffer,
                  pPropertyBufferSize,
                  PDWORD_RequiredSize,
                  **kwargs):

    Property = ctypes.c_ulong.from_address(pProperty)
    if (Property and Property.value == 0xC):
        PropertyBufferSize = ctypes.c_ulong.from_address(pPropertyBufferSize)
        if (PropertyBufferSize and PropertyBufferSize.value > 0):
            res = {}
            pPropertyBuffer = ctypes.c_ulong.from_address(PBYTE_PropertyBuffer)
            PropertyBuffer = ctypes.cast(pPropertyBuffer.value, ctypes.c_char_p)
            buffer = (ctypes.c_char * PropertyBufferSize.value).from_address(pPropertyBuffer.value)

            res['PropertyBufferSize'] = PropertyBufferSize.value
            res['original_PropertyBuffer'] = PropertyBuffer.value

            replace_string(buffer, PropertyBuffer, ['vmware', 'virtual'], [b'NewTek', b'Digital'])

            res['fixed_PropertyBuffer'] = PropertyBuffer.value

            return json.dumps(res)
