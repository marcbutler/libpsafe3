/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <errno.h>
#include <fcntl.h>

#include <psafe3.h>

#include "safe.h"
#include "util.h"

#include "crypto_gcrypt.h"

psafe3_err psafe3_setup() { return crypto_init(); }

psafe3_err psafe3_teardown() { return crypto_term(); }

psafe3_err psafe3_load(struct psafe3 *psafe, const char *path,
                       const unsigned char *password, size_t passlen)
{
    return gpg_err_code_from_errno(ENOSYS);
}

psafe3_err psafe3_store(struct psafe3 *psafe, const char *path,
                        const unsigned char *password, size_t passlen)
{
    return gpg_err_code_from_errno(ENOSYS);
}

psafe3_err psafe3_verify_password(const char          *path,
                                  const unsigned char *password, size_t passlen)
{
    union safe_prologue prologue;
    psafe3_err          err;
    int                 fd;
    sha256_hash         stretched_key;
    sha256_hash         stretched_key_hash;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return gpg_err_code_from_errno(errno);
    }

    err = safe_load_prologue(fd, &prologue);
    if (err != GPG_ERR_NO_ERROR) {
        goto close_and_exit;
    }

    err = crypto_stretch_key(password, passlen, prologue.fields.salt,
                             le32_deserialize(prologue.fields.iter),
                             stretched_key);
    if (err != GPG_ERR_NO_ERROR) {
        goto close_and_exit;
    }

    err = crypto_sha256md(stretched_key, stretched_key_hash, sizeof(sha256_hash));
    if (err != GPG_ERR_NO_ERROR) {
        goto close_and_exit;
    }

    if (memcmp(prologue.fields.h_pprime, stretched_key_hash, sizeof(sha256_hash)) != 0) {
        err = gpg_err_code_from_errno(EINVAL);
    }
    
close_and_exit:
    close(fd);
    return err;
}

void psafe3_free(struct psafe3 *psafe)
{
    assert_ptr(psafe);
    free(psafe->path);
}

const char *psafe3_strerror(psafe3_err err) { return gcry_strerror(err); }
