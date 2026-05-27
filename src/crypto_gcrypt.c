/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include "crypto_gcrypt.h"
#include "common.h"
#include "util.h"

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

    /*
     * After secure memory support is terminated, assume all secure heap memory
     * is now invalid.
     */
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

psafe3_err crypto_stretch_key(const unsigned char *pass, size_t passlen,
                              const sha256_hash salt, long iterations,
                              sha256_hash stretched_key)
{
    gcry_md_hd_t mdalgo;
    psafe3_err   err;
    sha256_hash  tmp;

    err = gcry_md_open(&mdalgo, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (CRYPTO_FAIL(err)) {
        return err;
    }

    gcry_md_write(mdalgo, pass, passlen);
    gcry_md_write(mdalgo, salt, sizeof(sha256_hash));
    memmove(tmp, gcry_md_read(mdalgo, 0), sizeof(tmp));

    assert(iterations > 0);
    while (iterations-- > 0) {
        gcry_md_reset(mdalgo);
        gcry_md_write(mdalgo, tmp, sizeof(tmp));
        memmove(tmp, gcry_md_read(mdalgo, 0), sizeof(tmp));
    }

    gcry_md_final(mdalgo);
    memmove(stretched_key, tmp, sizeof(sha256_hash));
    gcry_md_close(mdalgo);
    return GPG_ERR_NO_ERROR;
}

psafe3_err crypto_sha256md(const unsigned char *in, unsigned char *out,
                           size_t len)
{
    gcry_md_hd_t hd;
    gcry_error_t err;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (err != GPG_ERR_NO_ERROR) {
        goto exit_with_error;
    }
    gcry_md_write(hd, in, len);
    err = gcry_md_final(hd);
    if (err != GPG_ERR_NO_ERROR) {
        goto close_with_err;
    }

    const unsigned char *hash = gcry_md_read(hd, 0);
    if (hash == NULL) {
        goto close_with_err;
    }
    memmove(out, hash, sizeof(sha256_hash));

close_with_err:
    gcry_md_close(hd);
exit_with_error:
    return err;
}
