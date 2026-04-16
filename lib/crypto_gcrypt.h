#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include "common.h"

#include <gcrypt.h>

#define CRYPTO_OK(err) ((err) == GPG_ERR_NO_ERROR)

#define CRYPTO_FAIL(err) ((err) != GPG_ERR_NO_ERROR)

psafe3_err crypto_init();
psafe3_err crypto_term();

psafe3_err crypto_stretch_key(const unsigned char *pass, size_t passlen,
                              const sha256_hash salt, long iterations,
                              sha256_hash stretched_key);

psafe3_err crypto_sha256md(const unsigned char *in, unsigned char *out,
                           size_t len);
