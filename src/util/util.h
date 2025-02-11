#pragma once

#include "ioport.h"

#include <stdint.h>

#define KIB(n) ((n) * 1024)
#define MIB(n) ((n) * 1048576)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define BYTE uint8_t

/*
 * Load Little Endian 32 bit integer from memory location.
 * Memory may be unaligned.
 */
static inline uint32_t load_le32(void *mem)
{
    uint8_t *p = mem;
    uint32_t val = p[0];
    val = val + (p[1] << UINT32_C(8));
    val = val + (p[2] << UINT32_C(16));
    val = val + (p[3] << UINT32_C(24));
    return val;
}

#define STRIFY(txt) #txt

#define crash() crash_helper(__FILE__, __LINE__, __func__)

#define crash_helper(path, line, func)                                         \
    crash_actual(path ":" STRIFY(line) " ", func)

void crash_actual(const char *path, const char *func);

void util_close_fd(int fd);

int read_from_terminal(const char *prompt, char *buf, size_t *bufsize);
