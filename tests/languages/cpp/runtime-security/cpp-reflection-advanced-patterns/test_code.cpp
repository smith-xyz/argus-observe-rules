#include <dlfcn.h>

void dynamic_cast_ptr(void *handle, const char *sym) {
    void (*fn)(void) = (void (*)(void))dlsym(handle, sym);
    void *p = reinterpret_cast<void *>(fn);
}
