#include <string.h>

struct Foo { int x; int y; };

void copy_struct(struct Foo *dst, struct Foo *src) {
    memcpy(dst, src, sizeof(struct Foo));
    memmove(dst, src, sizeof(struct Foo));
}
