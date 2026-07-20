#include <cstdlib>
#include <cstring>

void unsafe_ops(void *dst, void *src, size_t count, void *ptr) {
    memcpy(dst, src, count);
    memmove(dst, src, count);
    realloc(ptr, count);
}
