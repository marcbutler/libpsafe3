#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "util.h"

#include "ioport.h"

static int _mmap_read(struct ioport *port, void *buf, const size_t len,
                      size_t *actual)
{
    assert(port != NULL && buf != NULL && actual != NULL);

    struct ioport_mmap *ctx;
    ctx = (void *)port;

    if (ctx->pos >= ctx->mem_size) {
        return 0;
    }
    size_t rdamt = MIN(ctx->mem_size - ctx->pos, len);
    uintptr_t loc = (uintptr_t)ctx->mem + ctx->pos;
    memmove(buf, (void *)loc, rdamt);
    ctx->pos += len;
    *actual = rdamt;
    return 0;
}

static int _mmap_close(struct ioport *port)
{
    assert(port != NULL);

    struct ioport_mmap *ctx;
    ctx = (void *)port;

    int ret = munmap(ctx->mem, ctx->mem_size);
    if (ret == 0) {
        ctx->mem = NULL;
        ctx->mem_size = 0;
        ctx->pos = 0;
    }
    return ret;
}

static int _mmap_can_read(struct ioport *port)
{
    assert(port != NULL);
    struct ioport_mmap *ctx = (void *)port;
    return ctx->pos < ctx->mem_size;
}

int ioport_mmap_open(const char *path, struct ioport **port)
{
    assert(path != NULL && port != NULL);

    int fd;
    if ((fd = open(path, O_RDWR)) < 0) {
        return -1;
    }

    struct stat nfo;
    if (fstat(fd, &nfo) != 0) {
        goto close_on_err;
    }

    void *memptr;
    memptr =
        mmap(NULL, nfo.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (memptr == MAP_FAILED) {
        goto close_on_err;
    }

    struct ioport_mmap *mmp;
    if (posix_memalign((void **)&mmp, sizeof(void *), sizeof(*mmp)) != 0) {
        goto close_on_err;
    }

    mmp->mem = memptr;
    mmp->mem_size = nfo.st_size;
    mmp->pos = 0;
    mmp->port.read = _mmap_read;
    mmp->port.close = _mmap_close;
    mmp->port.can_read = _mmap_can_read;
    *port = &mmp->port;
    return 0;

close_on_err:
    do {
        int errtmp = errno;
        util_close_fd(fd);
        errno = errtmp;
    } while (0);
    return -1;
}

int ioport_readn(struct ioport *port, void *buf, const size_t len)
{
    int ret;
    size_t rdamt;

    rdamt = 0;
    if ((ret = port->read(port, buf, len, &rdamt)) == 0) {
        return (rdamt != len) ? -1 : 0;
    }
    return ret;
}

int ioport_readle32(struct ioport *port, uint32_t *val)
{
    /*
     * Read little endian 32 bit integer.
     */
    assert(port != NULL && val != NULL);

    size_t rdamt;
    char buf[4];
    if (IOPORT_READ(port, buf, sizeof(buf), &rdamt) != 0 ||
        rdamt != sizeof(buf)) {
        return -1;
    }
    *val = load_le32(buf);
    return 0;
}
