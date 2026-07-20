def mutate(obj, name, value):
    setattr(obj, name, value)
    delattr(obj, name)
    g = globals()
    l = locals()
    return g, l
