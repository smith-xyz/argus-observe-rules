def check_types(obj, typ, cls, base):
    a = isinstance(obj, typ)
    b = issubclass(cls, base)
    return a, b
