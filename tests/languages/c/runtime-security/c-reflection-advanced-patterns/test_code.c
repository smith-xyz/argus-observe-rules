#include <dlfcn.h>

void dynamic_call(void *handle, const char *sym) {
    void (*fn)(void) = (void (*)(void))dlsym(handle, sym);
    fn();
}

void indirect_call(void *handle, const char *sym) {
    void *ptr = dlsym(handle, sym);
    ((void (*)(void))ptr)();
}
