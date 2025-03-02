/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <string.h>
#include <unistd.h>

#include "util.h"
#include "pws3.h"

int psafe3_parse_header(void *ptr, size_t size, struct pws3_header *hdr)
{
    static const char MAGIC[] = {'P', 'W', 'S', '3'};

    unsigned char *bytep = ptr;
    unsigned char *endp = ptr + size;

    if (memcmp(bytep, MAGIC, sizeof(MAGIC)) != 0) {
        goto exit_err;
    }
    bytep += sizeof(MAGIC);

#define READ_FIELD(fld)                                                        \
    do {                                                                       \
        size_t fldsz = sizeof(hdr->fld);                                       \
        if ((bytep + fldsz) > endp) {                                          \
            goto exit_err;                                                     \
        }                                                                      \
        memcpy(&hdr->fld, bytep, fldsz);                                         \
        bytep += fldsz;                                                          \
    } while (0)

    READ_FIELD(salt);

    if ((bytep + 4) > endp) {
        goto exit_err;
    }
    hdr->iter = le32_deserialize(bytep);
    bytep += 4;

    READ_FIELD(h_pprime);
    READ_FIELD(b);
    READ_FIELD(iv);

#undef READ_FIELD

    assert_ptr_diff(ptr, bytep, sizeof(struct pws3_header) + 4);
    return 0;

exit_err:
    return -1;
}

