#include <dlfcn.h>

void inspect_symbols(const char *lib, const char *sym) {
    void *handle = dlopen(lib, RTLD_LAZY);
    void *fn = dlsym(handle, sym);
    dlclose(handle);
}
