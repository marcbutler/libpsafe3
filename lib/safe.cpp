/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include "common.h"
#include "util.h"

#include "safe.h"

static const char MAGIC[] = {'P', 'W', 'S', '3'};

static const BYTE DBEOF[] = {'P', 'W', 'S', '3', '-', 'E', 'O', 'F',
                             'P', 'W', 'S', '3', '-', 'E', 'O', 'F'};

psafe3_err safe_load_prologue(int fd, union safe_prologue *prologue)
{
    off_t ret;
    ssize_t nread;

    assert_fd(fd);
    assert_ptr(prologue);

    ret = lseek(fd, 0, SEEK_SET);
    if (ret == -1)
        return gpg_err_code_from_errno(errno);

    nread = read(fd, prologue, sizeof(*prologue));
    if (nread == -1)
        return gpg_err_code_from_errno(errno);
    if (nread != sizeof(*prologue))
        return gpg_err_code_from_errno(EIO);

    if (memcmp(prologue->fields.magic, MAGIC, sizeof(MAGIC)) != 0)
        return gpg_err_code_from_errno(EINVAL);
    
    return GPG_ERR_NO_ERROR;
}
