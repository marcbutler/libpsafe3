#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <gcrypt.h>

#define CRYPTO_OK(err) ((err) == GPG_ERR_NO_ERROR)

#define CRYPTO_FAIL(err) ((err) != GPG_ERR_NO_ERROR)

extern gcry_error_t crypto_init();
extern gcry_error_t crypto_term();
