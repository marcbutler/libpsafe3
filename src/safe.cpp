// https://github.com/marcbutler/libpsafe3/LICENSE

#include "safe.h"
#include "common.h"
#include "util.h"

static const char MAGIC[] = {'P', 'W', 'S', '3'};

static const BYTE DBEOF[] = {'P', 'W', 'S', '3', '-', 'E', 'O', 'F',
                             'P', 'W', 'S', '3', '-', 'E', 'O', 'F'};

psafe3_err safe_load_prologue(int fd, unsigned char *prologue)
{
    off_t   ret;
    ssize_t nread;

    assert_fd(fd);
    assert_ptr(prologue);

    ret = lseek(fd, 0, SEEK_SET);
    if (ret == -1) {
        return gpg_err_code_from_errno(errno);
    }

    nread = read(fd, prologue, SAFE_PROLOGUE_SIZE);
    if (nread == -1) {
        return gpg_err_code_from_errno(errno);
    }
    if (nread != SAFE_PROLOGUE_SIZE) {
        return gpg_err_code_from_errno(EIO);
    }

    if (memcmp(prologue + SAFE_OFF_MAGIC, MAGIC, sizeof(MAGIC)) != 0) {
        return gpg_err_code_from_errno(EINVAL);
    }

    return GPG_ERR_NO_ERROR;
}

unsigned char const *safe_salt(struct safe *s)
{
    return (unsigned char const *)s->file_image + SAFE_OFF_SALT;
}

uint32_t safe_iter(struct safe *s)
{
    unsigned char const *b = (unsigned char const *)s->file_image + SAFE_OFF_ITER;
    uint32_t count = b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24);
    return count;
}

unsigned char const *safe_pass_hash(struct safe *s)
{
    return (unsigned char const *)s->file_image + SAFE_OFF_H_PPRIME;
}

unsigned char const *safe_b(struct safe *s, unsigned i)
{
    assert(i < 4);
    static const size_t offsets[4] = {
        SAFE_OFF_B1,
        SAFE_OFF_B2,
        SAFE_OFF_B3,
        SAFE_OFF_B4,
    };
    return (unsigned char const *)s->file_image + offsets[i];
}

unsigned char const *safe_iv(struct safe *s)
{
    return (unsigned char const *)s->file_image + SAFE_OFF_IV;
}
