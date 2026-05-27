#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define BYTE unsigned char

/* Twofish block size in bytes. */
#define TWOFISH_SIZE 16

/* SHA-256 size in bytes. */
#define SHA256_SIZE 32

/* Prevent linking to symbol. */
#define INTERNAL __attribute__((visibility("hidden")))

#define KIB(n) ((n) * 1024)
#define MIB(n) ((n) * 1048576)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define ABS(x) (((x) < 0) ? -(x) : (x))

#define assert_fd(f) assert((f) >= 0)

#define assert_ptr(p) assert((p) != NULL)

#define assert_not(e) assert(!(e))

#define STRIFY(txt) #txt

#define crash() crash_helper(__FILE__, __LINE__, __func__)

#define crash_helper(path, line, func)                                         \
    crash_actual(path ":" STRIFY(line) " ", func)

static inline uint32_t le32_deserialize(void *p)
{
    unsigned char *up = p;
    return up[0] + (up[1] << 8) + (up[2] << 16) + (up[3] << 24);
}

static inline void assert_ptr_diff(void *p1, void *p2, ptrdiff_t offset)
{
    uintptr_t addr1 = (uintptr_t)p1;
    uintptr_t addr2 = (uintptr_t)p2;
    ptrdiff_t diff = addr2 - addr1;
    assert(ABS(diff) == offset);
}

void crash_actual(const char *path, const char *func);
void checked_close(int fd);
int  read_from_terminal(const char *prompt, char *buf, size_t *bufsize);
void wperror(wchar_t *msg);
