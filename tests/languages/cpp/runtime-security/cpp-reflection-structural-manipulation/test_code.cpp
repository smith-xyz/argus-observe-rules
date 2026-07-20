#include <cstring>

struct Foo { int x; int y; };

void copy_struct(Foo *dst, Foo *src) {
    memcpy(dst, src, sizeof(Foo));
    memmove(dst, src, sizeof(Foo));
}
