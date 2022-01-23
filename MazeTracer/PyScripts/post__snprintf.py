import ctypes
import json


def post_analyzer(char_buffer,
                  size_t_count,
                  char_format,
                  **kwargs):

    buf = ctypes.c_char_p.from_address(char_buffer)
    size = ctypes.c_long.from_address(size_t_count)
    res = {}
    if buf and size:
        res['buffer'] = str(buf.value[0:size.value])
        res['size'] = size.value
    return json.dumps(res)
