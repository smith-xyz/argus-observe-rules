int call_direct(int (*fn)(int)) {
    return fn(1);
}
