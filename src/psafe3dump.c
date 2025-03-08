/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <wchar.h>
#include <unistd.h>

#include "psafe3/psafe.h"
#include "psafe3/pws3.h"

#include "psafe3.h"
#include "psafe3/util.h"

static void gcrypt_fatal(gcry_error_t err)
{
    fwprintf(stderr, L"gcrypt error %s/%s\n", gcry_strsource(err),
             gcry_strerror(err));
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int ret;
    char pass[100];
    setlocale(LC_ALL, "");

    if (argc != 2 && argc != 3) {
        wprintf(L"Usage: psafe file.psafe3\n");
        exit(EXIT_FAILURE);
    }

    if (argc == 3) {
        strcpy(pass, argv[2]);
    } else {
        size_t passmax = sizeof(pass);
        if (read_from_terminal("Password: ", pass, &passmax) != 0) {
            wprintf(L"No password read.");
            exit(EXIT_FAILURE);
        }
    }

    if (psafe3_setup() != 0) {
        wprintf(L"Failed to initialize psafe3 library.");
        exit(EXIT_FAILURE);
    }

    int fd;
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        wperror(L"open()");
        exit(EXIT_FAILURE);
    }

    struct stat file_info;
    if (fstat(fd, &file_info) < 0) {
        wperror(L"fstat()");
        exit(EXIT_FAILURE);
    }
    size_t sz;
    sz = file_info.st_size;

    unsigned char *ptr;
    ptr = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        wperror(L"mmap()");
        exit(EXIT_FAILURE);
    }

    struct pws3_header hdr;
    if (psafe3_parse_header(ptr, sz, &hdr) != 0) {
        fwprintf(stderr, L"Error reading psafe3 header.");
        exit(EXIT_FAILURE);
    }

    checked_close(fd);
    /*
     * After closing the file descriptor unmapping the memory will close the
     * file handle.
     */

    struct safe_sec *sec;
    sec = gcry_malloc_secure(sizeof(*sec));
    if (sec == NULL) {
        wprintf(L"Failed to allocate secure memory.\n");
        exit(EXIT_FAILURE);
    }

    ret = stretch_and_check_pass(pass, strlen(pass), &hdr, sec);
    if (ret != 0) {
        gcry_free(sec);
        wprintf(L"Invalid password.\n");
        exit(1);
    }

    uint8_t *safe;
    size_t safe_size;
    safe_size = sz - (4 + sizeof(hdr) + 48);
    assert(safe_size > 0);
    assert(safe_size % TWOFISH_SIZE == 0);
    safe = gcry_malloc_secure(safe_size);
    if (safe == NULL) {
        wprintf(L"Failed to allocate secure memory.\n");
        exit(EXIT_FAILURE);
    }

    gcry_error_t gerr;
    struct crypto_ctx ctx;
    if (init_decrypt_ctx(&ctx, &hdr, sec) < 0) {
        gcrypt_fatal(ctx.gerr);
    }

    size_t bcnt;
    bcnt = safe_size / TWOFISH_SIZE;
    assert(bcnt > 0);
    uint8_t *encp;
    uint8_t *safep;
    encp = ptr + 4 + sizeof(hdr);
    safep = safe;
    uint8_t *safe_end = safep + safe_size;
    while (bcnt && (safep < safe_end)) {
        gerr = gcry_cipher_decrypt(ctx.cipher, safep, TWOFISH_SIZE, encp,
                                   TWOFISH_SIZE);
        if (gerr != GPG_ERR_NO_ERROR) {
            gcrypt_fatal(gerr);
        }
        safep += TWOFISH_SIZE;
        encp += TWOFISH_SIZE;
        bcnt--;
    }
    assert(bcnt == 0);

    enum { HDR, DB };
    int state = HDR;
    safep = safe;
    while (safep < safe + safe_size) {
        struct field *fld;
        fld = (struct field *)safep;
        wprintf(L"type=%02x  len=%-3u  ", fld->type, fld->len);
        if (state == DB) {
            dump_db_field(stdout, fld);
        } else {
            dump_hdr_field(stdout, fld);
        }
        if (fld->type == 0xff) {
            state = DB;
        }
        putwc('\n', stdout);
        if (fld->len) {
            gcry_md_write(ctx.hmac, safep + sizeof(*fld), fld->len);
        }
        safep += ((fld->len + 5 + 15) / TWOFISH_SIZE) * TWOFISH_SIZE;
    }

    assert(memcmp(ptr + (sz - 48), "PWS3-EOFPWS3-EOF", TWOFISH_SIZE) == 0);

#define EOL() putwc('\n', stdout)
    EOL();
    dump_prologue(stdout, &hdr);
    wprintf(L"KEY    ");
    dump_bytes(stdout, sec->pprime, SHA256_SIZE);
    EOL();
    wprintf(L"H(KEY) ");
    dump_bytes(stdout, hdr.h_pprime, SHA256_SIZE);
    EOL();

    gcry_md_final(ctx.hmac);
    wprintf(L"HMAC'  ");
    uint8_t hmac[32];
    memmove(hmac, gcry_md_read(ctx.hmac, GCRY_MD_SHA256), SHA256_SIZE);
    dump_bytes(stdout, hmac, SHA256_SIZE);
    EOL();

    wprintf(L"HMAC   ");
    dump_bytes(stdout, ptr + (sz - SHA256_SIZE), SHA256_SIZE);
    EOL();
#undef EOL

    gcry_free(safe);
    gcry_free(sec);

    term_decrypt_ctx(&ctx);
    if (psafe3_teardown() != 0) {
        wprintf(L"Error terminating psafe3 library.");
        exit(EXIT_FAILURE);
    }

    ret = munmap(ptr, sz);
    if (ret < 0) {
        wperror(L"munmap()");
    }

    exit(0);
}
