#include <wchar.h>

#include "crypto.h"

void gcrypt_fatal(gcry_error_t err)
{
    fwprintf(stderr, L"gcrypt error %s/%s\n", gcry_strsource(err),
             gcry_strerror(err));
    exit(EXIT_FAILURE);
}

void crypto_init(size_t secmem_pool_size)
{
    gcry_error_t gerr;
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fputws(L"Fatal libgcrypt version mismatch.\n", stdout);
        exit(EXIT_FAILURE);
    }

    /* Create a pool of secure memory. */
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gerr = gcry_control(GCRYCTL_INIT_SECMEM, secmem_pool_size, 0);
    if (gerr != GPG_ERR_NO_ERROR)
        gcrypt_fatal(gerr);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

void crypto_term(void)
{
    gcry_error_t gerr;
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gerr = gcry_control(GCRYCTL_TERM_SECMEM);
    if (gerr != GPG_ERR_NO_ERROR)
        gcrypt_fatal(gerr);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
}
