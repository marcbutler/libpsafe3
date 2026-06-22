/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "psafe3.h"

#include "crypto.h"
#include "safe.h"
#include "util.h"

psafe3_err psafe3_load(psafe3_handle *safe, const char *path)
{
    assert(safe != NULL && path != NULL);

    int fd;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return gcry_error_from_errno(errno);
    }

    struct stat stbuf;
    if (fstat(fd, &stbuf)) {
        (void)close(fd);
        return gcry_error_from_errno(errno);
    }

    /* TODO Check that the file meets the minimum size expectation. */

    void *memptr;
    memptr = mmap(NULL, stbuf.st_size, PROT_READ, MAP_FILE, fd, 0);
    (void)close(fd);
    if (memptr == MAP_FAILED) {
        return gcry_error_from_errno(errno);
    }

    struct safe *psafe;
    psafe = (struct safe *)malloc(sizeof(*psafe) + strlen(path) + 1);
    psafe->file_image = (uintptr_t)memptr;
    psafe->file_size = stbuf.st_size;
    memcpy(&psafe->path, path, strlen(path) + 1);

    *safe = psafe;
    return PSAFE3_OK;
}

psafe3_err psafe3_unload(psafe3_handle *safe)
{
    struct safe *psafe;
    psafe = (struct safe *)*safe;
    if (munmap((void *)psafe->file_image, psafe->file_size) < 0) {
        return gcry_error_from_errno(errno);
    }
    free(psafe);
    return PSAFE3_OK;
}

psafe3_err psafe3_setup()
{
    return crypto_init();
}

psafe3_err psafe3_teardown()
{
    return crypto_term();
}

psafe3_err psafe3_verify_password(const char          *path,
                                  const unsigned char *password, size_t passlen)
{
    unsigned char prologue[SAFE_PROLOGUE_SIZE];
    psafe3_err    err;
    int           fd;
    sha256_hash   stretched_key;
    sha256_hash   stretched_key_hash;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return gpg_err_code_from_errno(errno);
    }

    err = safe_load_prologue(fd, prologue);
    if (err != GPG_ERR_NO_ERROR) {
        goto close_and_exit;
    }

    err = crypto_stretch_key(password, passlen, prologue + SAFE_OFF_SALT,
                             le32_deserialize(prologue + SAFE_OFF_ITER),
                             stretched_key);
    if (err != GPG_ERR_NO_ERROR) {
        goto close_and_exit;
    }

    err = crypto_sha256md(stretched_key, stretched_key_hash, sizeof(sha256_hash));
    if (err != GPG_ERR_NO_ERROR) {
        goto close_and_exit;
    }

    if (memcmp(prologue + SAFE_OFF_H_PPRIME, stretched_key_hash, sizeof(sha256_hash)) != 0) {
        err = gpg_err_code_from_errno(EINVAL);
    }

close_and_exit:
    close(fd);
    return err;
}

const char *psafe3_strerror(psafe3_err err)
{
    return gcry_strerror(err);
}

psafe3_err psafe3_get_prologue(psafe3_handle safe, struct psafe3_prologue *prologue)
{
    assert(safe != NULL && prologue != NULL);
    struct safe *psafe = (struct safe *)safe;
    memcpy(prologue->salt, safe_salt(psafe), PSAFE3_SIZE_SALT);
    prologue->iter = safe_iter(psafe);
    memcpy(prologue->pass_hash, safe_pass_hash(psafe), PSAFE3_SIZE_PASS_HASH);
    memcpy(prologue->b1, safe_b(psafe, 0), PSAFE3_SIZE_B);
    memcpy(prologue->b2, safe_b(psafe, 1), PSAFE3_SIZE_B);
    memcpy(prologue->b3, safe_b(psafe, 2), PSAFE3_SIZE_B);
    memcpy(prologue->b4, safe_b(psafe, 3), PSAFE3_SIZE_B);
    memcpy(prologue->iv, safe_iv(psafe), PSAFE3_SIZE_IV);
    return PSAFE3_OK;
}
