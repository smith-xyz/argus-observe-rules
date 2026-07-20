def call_dynamic(obj, name):
    result = getattr(obj, name)()
    method = getattr(obj, name)
    out = method()
    return result, out
