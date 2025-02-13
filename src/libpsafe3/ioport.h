#pragma once
// https://github.com/marcbutler/psafe/LICENSE

// Unified interface for performing IO to both files and memory.
// Idea inspired by Scheme/Racket https://racket-lang.org/. See also SDL
// https://www.libsdl.org/ SDL_IOStreamInterface.

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#define BYTE uint8_t

#define IOPORT_READABLE UINTMAX_C(0x1)
#define IOPORT_WRITABLE UINTMAX_C(0x2)
#define IOPORT_GROWABLE UINTMAX_C(0x10)
#define IOPORT_SEEKABLE UINTMAX_C(0x20)

struct ioport {
    uintmax_t attr; // TODO Unimplemented
    int (*read)(struct ioport *port, void *buf, const size_t max,
                size_t *actual);
    int (*close)(struct ioport *port);
    int (*can_read)(struct ioport *port);
    int (*can_write)(struct ioport *port);
    off_t (*where)(struct ioport *port);
};

int ioport_readn(struct ioport *port, void *buf, const size_t max);
int ioport_readle32(struct ioport *port, uint32_t *val);

#define IOPORT_READ(port, buf, max, p_actual)                                  \
    ((port)->read(port, buf, max, p_actual))

#define IOPORT_CAN_READ(port) ((port)->can_read(port))

#define IOPORT_READN(port, buf, len) ioport_readn(port, buf, len)

struct ioport_mmap {
    struct ioport port;
    void *mem;
    size_t mem_size;
    size_t pos;
};

int ioport_mmap_open(const char *path, struct ioport **port);
