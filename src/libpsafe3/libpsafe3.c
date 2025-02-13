// https://github.com/marcbutler/psafe/LICENSE

#include <errno.h>
#include <stdlib.h>

#include "lib.internal.h"

#include "crypto_gcrypt.h"

int libpsafe3_init()
{
    gcry_error_t err;
    err = crypto_init();
    if (!CRYPTO_OK(err)) {
        return -1;
    }
    return 0;
}

int libpsafe3_term()
{
    gcry_error_t err;
    err = crypto_term();
    if (!CRYPTO_OK(err)) {
        return -1;
    }
    return 0;
}
