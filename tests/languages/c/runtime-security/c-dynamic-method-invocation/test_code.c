#include <dlfcn.h>

void call_dynamic(void *handle, const char *name) {
    int (*fn)(int) = (int (*)(int))dlsym(handle, name);
    fn(42);
}

void call_with_args(void *handle, const char *name, int arg) {
    int (*method)(int) = (int (*)(int))dlsym(handle, name);
    method(arg);
}
