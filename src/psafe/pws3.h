#pragma once

#include "util/ioport.h"

/* The format defines the header as being the first set of records, so
 * call this the prologue.
 */
#include <stdint.h>
typedef struct pws3_header {
    /* Starts with the fixed tag "PWS3". */
    uint8_t  salt[32];
    uint32_t iter;
    uint8_t  h_pprime[32];
    uint8_t  b[4][16];
    uint8_t  iv[16];
} pws3_header;

int pws3_read_header(struct ioport *port, pws3_header *hdr);
