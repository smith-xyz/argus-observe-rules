def inspect_object(obj, cls, name):
    t = type(obj)
    ok = isinstance(obj, cls)
    attr = getattr(obj, name)
    present = hasattr(obj, name)
    v = vars(obj)
    names = dir(obj)
    return t, ok, attr, present, v, names
