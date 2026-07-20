import importlib

def dynamic_import(name, expr, code):
    mod = __import__(name)
    loaded = importlib.import_module(name)
    result = eval(expr)
    exec(code)
    return mod, loaded, result
