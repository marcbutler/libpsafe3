#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "util/util.h"
#include "pws3.h"

int pws3_read_header(IOPort *port, pws3_header *hdr)
{
    static const char MAGIC[] = {'P', 'W', 'S', '3'};

    char magic[4];
    if (ioport_read_exactly(port, magic, sizeof(magic)) != 0) {
        goto exit_err;
    }
    if (memcmp(magic, MAGIC, sizeof(magic)) != 0) {
        goto exit_err;
    }

#define READ_FIELD(fld)                                                        \
    if (ioport_read_exactly(port, &hdr->fld, sizeof(hdr->fld)) != 0)           \
    goto exit_err

    READ_FIELD(salt);

    if (ioport_read_le32(port, &hdr->iter) != 0) {
        goto exit_err;
    }

    READ_FIELD(h_pprime);
    READ_FIELD(b);
    READ_FIELD(iv);

#undef READ_FIELD
    return 0;

exit_err:
    return -1;
}
