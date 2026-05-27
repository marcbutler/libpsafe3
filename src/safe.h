#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include "common.h"

struct safe_prologue_fields {
    unsigned char magic[4];
    unsigned char salt[32];
    unsigned char iter[4];
    unsigned char h_pprime[SHA256_BYTES];
    unsigned char b1[16];
    unsigned char b2[16];
    unsigned char b3[16];
    unsigned char b4[16];
    unsigned char iv[16];
} __attribute__((packed));

union safe_prologue {
    struct safe_prologue_fields fields;
    unsigned char bytes[sizeof(struct safe_prologue_fields)];
};

psafe3_err safe_load_prologue(int fd, union safe_prologue *prologue);
