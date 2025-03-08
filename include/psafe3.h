#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <stdint.h>
#include <stdlib.h>

typedef unsigned int psafe3_err;

#define PSAFE3_SUCCESS 0

struct psafe3 {
    void *state;
    char *path;
};

psafe3_err  psafe3_setup();
psafe3_err  psafe3_teardown();
psafe3_err  psafe3_load(struct psafe3 *psafe, const char *path,
                        const unsigned char *password, size_t passlen);
psafe3_err  psafe3_store(struct psafe3 *psafe, const char *path,
                         const unsigned char *password, size_t passlen);
psafe3_err  psafe3_verify_password(const char          *path,
                                   const unsigned char *password,
                                   size_t               passlen);
void        psafe3_free(struct psafe3 *psafe);
const char *psafe3_strerror(psafe3_err err);
