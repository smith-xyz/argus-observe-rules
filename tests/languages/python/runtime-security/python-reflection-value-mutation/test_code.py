def mutate_values(obj, name, value):
    setattr(obj, name, value)
    object.__setattr__(obj, name, value)
