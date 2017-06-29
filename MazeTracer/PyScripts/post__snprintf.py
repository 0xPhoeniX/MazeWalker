import ctypes
import json

def post_analyzer(char_buffer,
                  size_t_count,
                  char_format,
                  **kwargs):

    buf = ctypes.c_char_p.from_address(char_buffer)
    size = ctypes.c_long.from_address(size_t_count)
    res = []
    if buf and buf.value and size and size.value:
        data = str(buf.value[0:size.value])
        result = {'name': 'buffer', 'data': data}
        res.append(result)

    return json.dumps(res)
