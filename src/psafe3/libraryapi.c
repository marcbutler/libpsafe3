/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <errno.h>

#include "util.h"

#include "crypto_gcrypt.h"

int psafe3_setup()
{
    gcry_error_t err;
    err = crypto_init();
    if (CRYPTO_FAIL(err)) {
        return -1;
    }
    return 0;
}

int psafe3_teardown()
{
    gcry_error_t err;
    err = crypto_term();
    if (CRYPTO_FAIL(err)) {
        return -1;
    }
    return 0;
}
