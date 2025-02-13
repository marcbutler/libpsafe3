#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "libpsafe3/util.h"

int main(int argc, char **argv)
{
    uint32_t v;

    (void)argc;
    (void)argv;

    static const uint8_t testv1[] = {1, 0, 0, 0};
    v = load_le32((void *)testv1);
    if (v != 1)
        crash();

    static const uint8_t testv2[] = {254, 255, 255, 255};
    v = load_le32((void *)testv2);
    if (v != UINT32_MAX - 1)
        crash();

    return 0;
}
