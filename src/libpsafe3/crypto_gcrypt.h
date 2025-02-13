#pragma once
// https://github.com/marcbutler/psafe/LICENSE

#include <gcrypt.h>

#define CRYPTO_OK(err) ((err) == GPG_ERR_NO_ERROR)

extern gcry_error_t crypto_init();
extern gcry_error_t crypto_term();
