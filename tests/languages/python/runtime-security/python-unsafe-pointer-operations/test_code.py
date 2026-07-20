import ctypes

def unsafe_ops(buf, count):
    ptr = ctypes.cast(buf, ctypes.c_void_p)
    arr = ctypes.POINTER(ctypes.c_char)
    ctypes.memmove(buf, buf, count)
    void_p = ctypes.c_void_p(0)
    return ptr, arr, void_p
