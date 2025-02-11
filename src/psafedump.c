#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <wchar.h>

#include "util/util.h"

#include "psafe/psafe.h"
#include "psafe/pws3.h"

#include "libpsafe3/libpsafe3.h"

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

    if (libpsafe3_init() != 0) {
        wprintf(L"Failed to initialize psafe3 library.");
        exit(EXIT_FAILURE);
    }

    struct ioport *safe_io = NULL;
    if (ioport_mmap_open(argv[1], &safe_io) != 0) {
        wprintf(L"Error opening file: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct ioport_mmap *mmio = (void *)safe_io;
    uint8_t *ptr = mmio->mem;
    size_t sz = mmio->mem_size;
    struct pws3_header hdr;
    if (pws3_read_header(safe_io, &hdr) != 0) {
        fwprintf(stderr, L"Error reading header.");
        exit(EXIT_FAILURE);
    }

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
    assert(safe_size % TWOFISH_BLOCK_SIZE == 0);
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
    bcnt = safe_size / TWOFISH_BLOCK_SIZE;
    assert(bcnt > 0);
    uint8_t *encp;
    uint8_t *safep;
    encp = ptr + 4 + sizeof(hdr);
    safep = safe;
    while (bcnt && IOPORT_CAN_READ(safe_io)) {
        gerr = gcry_cipher_decrypt(ctx.cipher, safep, TWOFISH_BLOCK_SIZE, encp,
                                   TWOFISH_BLOCK_SIZE);
        if (gerr != GPG_ERR_NO_ERROR) {
            gcrypt_fatal(gerr);
        }
        safep += TWOFISH_BLOCK_SIZE;
        encp += TWOFISH_BLOCK_SIZE;
        bcnt--;
    }
    wprintf(L"bcnt==%lu\n", bcnt);
    assert(bcnt == 0);

    enum { HDR, DB };
    int state = HDR;
    safep = safe;
    while (safep < safe + safe_size) {
        struct field *fld;
        fld = (struct field *)safep;
        wprintf(L"len=%-3u  type=%02x  ", fld->len, fld->type);
        if (state == DB)
            db_print(stdout, fld);
        else
            hd_print(stdout, fld);
        if (fld->type == 0xff)
            state = DB;
        putwc('\n', stdout);
        if (fld->len)
            gcry_md_write(ctx.hmac, safep + sizeof(*fld), fld->len);
        safep +=
            ((fld->len + 5 + 15) / TWOFISH_BLOCK_SIZE) * TWOFISH_BLOCK_SIZE;
    }

    assert(memcmp(ptr + (sz - 48), "PWS3-EOFPWS3-EOF", TWOFISH_BLOCK_SIZE) ==
           0);

#define EOL() putwc('\n', stdout)
    EOL();
    print_prologue(stdout, &hdr);
    wprintf(L"KEY    ");
    printhex(stdout, sec->pprime, 32);
    EOL();
    wprintf(L"H(KEY) ");
    printhex(stdout, hdr.h_pprime, 32);
    EOL();

    gcry_md_final(ctx.hmac);
    wprintf(L"HMAC'  ");
    uint8_t hmac[32];
    memmove(hmac, gcry_md_read(ctx.hmac, GCRY_MD_SHA256), 32);
    printhex(stdout, hmac, 32);
    EOL();

    wprintf(L"HMAC   ");
    printhex(stdout, ptr + (sz - 32), 32);
    EOL();
#undef EOL

    gcry_free(safe);
    gcry_free(sec);

    safe_io->close(safe_io);
    term_decrypt_ctx(&ctx);

    if (libpsafe3_term() != 0) {
        wprintf(L"Error terminating psafe3 library.");
        exit(EXIT_FAILURE);
    }

    exit(0);
}
