#pragma once

#include <stdint.h>

/*
 * File format.
 *
 * OFF SZ NAME
 *   0  4 MAGIC
 *   4 32 SALT
 *  36  4 ITER
 *  40 32 H(P')
 *  72 16 B1
 *  88 16 B2
 * 104 16 B3
 * 120 16 B4
 * 136 16 IV
 *
 *  Field
 *   0  4 LENGTH
 *   4  1 TYPE
 *   5  * FIELD DATA
 * 
 */

struct pws3_header {
    /* Starts with the fixed tag "PWS3". */
    uint8_t  salt[32];
    uint32_t iter;
    uint8_t  h_pprime[32];
    uint8_t  b[4][16];
    uint8_t  iv[16];
};

int psafe3_parse_header(void *ptr, size_t size, struct pws3_header *hdr);
