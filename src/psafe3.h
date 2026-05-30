#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <stdint.h>
#include <stdlib.h>

typedef unsigned int psafe3_err;
typedef void * psafe3_handle;

enum safe_prologue_size {
     PSAFE3_SIZE_MAGIC = 4,
     PSAFE3_SIZE_SALT = 32,
     PSAFE3_SIZE_ITER = 4,
     PSAFE3_SIZE_PASS_HASH = 32,
     PSAFE3_SIZE_B = 16,
     PSAFE3_SIZE_IV = 16
};

struct psafe3_prologue {
    uint8_t  salt[PSAFE3_SIZE_SALT];
    uint32_t iter;
    uint8_t  pass_hash[PSAFE3_SIZE_PASS_HASH];
    uint8_t  b1[PSAFE3_SIZE_B];
    uint8_t  b2[PSAFE3_SIZE_B];
    uint8_t  b3[PSAFE3_SIZE_B];
    uint8_t  b4[PSAFE3_SIZE_B];
    uint8_t  iv[PSAFE3_SIZE_IV];
};

#define PSAFE3_OK (psafe3_err)0

psafe3_err  psafe3_setup();
psafe3_err  psafe3_teardown();
psafe3_err  psafe3_verify_password(const char          *path,
                                   const unsigned char *password,
                                   size_t               passlen);
const char *psafe3_strerror(psafe3_err err);
psafe3_err psafe3_load(psafe3_handle *safe, const char *path);
psafe3_err psafe3_unload(psafe3_handle *safe);
psafe3_err psafe3_get_prologue(psafe3_handle safe, struct psafe3_prologue *prologue);
