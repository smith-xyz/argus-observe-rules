#include <string.h>

void mutate_values(int *ptr, int value) {
    *ptr = value;
    int local = value;
    memcpy(ptr, &local, sizeof(int));
}
