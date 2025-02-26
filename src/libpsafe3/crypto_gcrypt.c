// https://github.com/marcbutler/psafe/LICENSE

#include "internal.h"

#include "crypto_gcrypt.h"

#define GCRY_FAILED(err) ((err) != GPG_ERR_NO_ERROR)

gcry_error_t crypto_init()
{
    if (!gcry_check_version(GCRYPT_VERSION)) {
        /* TODO Provide diagnostic information. */
        return -1;
    }

    gcry_error_t err;
    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    // Initialize secure memory pool to default size; currently 16KiB.
    err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    // Allow on the fly expansion of the secure memory area. Minimum increment
    // is 32KiB.
    err = gcry_control(GCRYCTL_AUTO_EXPAND_SECMEM, 1);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    return GPG_ERR_NO_ERROR;
}

gcry_error_t crypto_term()
{
    gcry_error_t err;
    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    if (GCRY_FAILED(err)) {
        return err;
    }

    // Clean up ALL secure memory. Assume that if the caller is holding onto any
    // memory allocated through gcrypt accessing that memory after this call
    // is an error.
    err = gcry_control(GCRYCTL_TERM_SECMEM);
    if (GCRY_FAILED(err)) {
        return err;
    }

    err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    if (GCRY_FAILED(err)) {
        return err;
    }

    return GPG_ERR_NO_ERROR;
}
