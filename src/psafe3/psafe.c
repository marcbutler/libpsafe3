/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <errno.h>
#include <gcrypt.h>
#include <getopt.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include "psafe.h"
#include "pws3.h"
#include "util.h"

static void gcrypt_fatal(gcry_error_t err)
{
    fwprintf(stderr, L"gcrypt error %s/%s\n", gcry_strsource(err),
             gcry_strerror(err));
    exit(EXIT_FAILURE);
}

INTERNAL void stretch_key(const char *pass, size_t passlen,
                          const struct pws3_header *pro, uint8_t *skey)
{
    gcry_error_t gerr;
    gcry_md_hd_t sha256;
    gerr = gcry_md_open(&sha256, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (gerr != GPG_ERR_NO_ERROR) {
        gcrypt_fatal(gerr);
    }

    gcry_md_write(sha256, pass, passlen);
    gcry_md_write(sha256, pro->salt, SHA256_SIZE);
    memmove(skey, gcry_md_read(sha256, 0), SHA256_SIZE);

    uint32_t iter = pro->iter;
    while (iter-- > 0) {
        gcry_md_reset(sha256);
        gcry_md_write(sha256, skey, SHA256_SIZE);
        memmove(skey, gcry_md_read(sha256, 0), SHA256_SIZE);
    }
    gcry_md_close(sha256);
}

INTERNAL gcry_error_t sha256_md(const uint8_t *in, uint8_t *out, size_t len)
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
        goto exit_with_error;
    }

    const uint8_t *hash = gcry_md_read(hd, 0);
    if (hash == NULL) {
        goto exit_with_error;
    }
    memmove(out, hash, SHA256_SIZE);
    gcry_md_close(hd);

exit_with_error:
    return err;
}

/**
 * @brief Extract the random key from the header.
 *
 * @param stretchkey Verified stretched key.
 * @param fst Block B1.
 * @param snd Block B2.
 * @param randkey Random key storage.
 * @return Error status.
 */
INTERNAL gcry_error_t extract_random_key(const uint8_t *stretchkey,
                                         const uint8_t *fst, const uint8_t *snd,
                                         uint8_t *randkey)
{
    gcry_error_t     gerr;
    gcry_cipher_hd_t hd;
    gerr = gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB,
                            GCRY_CIPHER_SECURE);
    if (gerr != GPG_ERR_NO_ERROR) {
        return gerr;
    }
    gerr = gcry_cipher_setkey(hd, stretchkey, SHA256_SIZE);
    if (gerr != GPG_ERR_NO_ERROR) {
        return gerr;
    }
    gcry_cipher_decrypt(hd, randkey, TWOFISH_SIZE, fst, TWOFISH_SIZE);
    gcry_cipher_reset(hd);
    gcry_cipher_decrypt(hd, randkey + TWOFISH_SIZE, TWOFISH_SIZE, snd,
                        TWOFISH_SIZE);
    gcry_cipher_close(hd);
    return GPG_ERR_NO_ERROR;
}

void print_time(uint8_t *val)
{
    struct tm *lt;
    time_t     time;
    time = le32_deserialize(val);
    lt = gmtime(&time);
    wprintf(L"%d-%d-%d %02d:%02d:%02d", 1900 + lt->tm_year, lt->tm_mon,
            lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
}

void dump_bytes(FILE *f, uint8_t *ptr, unsigned cnt)
{
    unsigned i;
    for (i = 0; i < cnt; i++) {
        fwprintf(f, L"%02x", *ptr++);
    }
}

void print_uuid(uint8_t *uuid)
{
    dump_bytes(stdout, uuid, 4);
    putwc('-', stdout);
    dump_bytes(stdout, uuid + 4, 2);
    putwc('-', stdout);
    dump_bytes(stdout, uuid + 6, 2);
    putwc('-', stdout);
    dump_bytes(stdout, uuid + 8, 2);
    putwc('-', stdout);
    dump_bytes(stdout, uuid + 10, 6);
}

/* Print out utf-8 string. */
void pws(FILE *f, uint8_t *bp, size_t len)
{
    mbstate_t state;
    memset(&state, 0, sizeof(state));
    wchar_t *tmp;
    tmp = malloc((len + 1) * sizeof(wchar_t));
    size_t      n;
    const char *ptr = (const char *)bp;
    n = mbsrtowcs(tmp, &ptr, len, &state);
    tmp[n] = L'\0';
    fputws(tmp, f);
    free(tmp);
}

void dump_hdr_field(FILE *f, struct field *fld)
{
    switch (fld->type) {
    case 0x2 ... 0x3:
    case 0x5 ... 0xb:
    case 0xf ... 0x11:
        pws(f, fld->val, fld->len);
        break;
    case 0x1:
        print_uuid(fld->val);
        break;
    case 0x4:
        print_time(fld->val);
        break;
    }
}

void dump_db_field(FILE *f, struct field *fld)
{
    switch (fld->type) {
    case 0x2 ... 0x6:
    case 0xd ... 0x10:
    case 0x14:
    case 0x16:
        pws(f, fld->val, fld->len);
        break;
    case 0x7 ... 0xa:
    case 0xc:
        print_time(fld->val);
        break;
    case 0x1:
        print_uuid(fld->val);
        break;
    }
}

int init_decrypt_ctx(struct crypto_ctx *ctx, struct pws3_header *pro,
                     struct safe_sec *sec)
{

    assert_ptr(ctx);
    assert_ptr(pro);
    assert_ptr(sec);

    gcry_error_t gerr;
    gerr = gcry_cipher_open(&ctx->cipher, GCRY_CIPHER_TWOFISH,
                            GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    if (gerr != GPG_ERR_NO_ERROR) {
        goto err_cipher;
    }

    ctx->gerr = gcry_cipher_setkey(ctx->cipher, sec->rand_k, SHA256_SIZE);
    if (gerr != GPG_ERR_NO_ERROR) {
        goto err_cipher;
    }

    ctx->gerr = gcry_cipher_setiv(ctx->cipher, pro->iv, TWOFISH_SIZE);
    if (gerr != GPG_ERR_NO_ERROR) {
        goto err_cipher;
    }

    gerr = gcry_md_open(&ctx->hmac, GCRY_MD_SHA256,
                        GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
    if (gerr != GPG_ERR_NO_ERROR) {
        goto err_hmac;
    }

    gerr = gcry_md_setkey(ctx->hmac, sec->rand_l, SHA256_SIZE);
    if (gerr != GPG_ERR_NO_ERROR) {
        goto err_hmac;
    }

    return 0;

err_hmac:
    gcry_cipher_close(ctx->cipher);
err_cipher:
    ctx->gerr = gerr;
    return -1;
}

void term_decrypt_ctx(struct crypto_ctx *ctx)
{
    gcry_cipher_close(ctx->cipher);
    gcry_md_close(ctx->hmac);
}

void dump_prologue(FILE *f, struct pws3_header *pro)
{
    int i;
#define EOL() fputwc('\n', f)
    fputws(L"SALT   ", f);
    dump_bytes(f, pro->salt, 32);
    EOL();
    fwprintf(f, L"ITER   %" PRIu32 L"\n", pro->iter);
    fputws(L"H(P')  ", f);
    dump_bytes(f, pro->h_pprime, SHA256_SIZE);
    EOL();
    for (i = 0; i < 4; i++) {
        fwprintf(f, L"B%d     ", i);
        dump_bytes(f, pro->b[i], 16);
        EOL();
    }
    fputws(L"IV     ", f);
    dump_bytes(f, pro->iv, 16);
    EOL();
#undef EOL
}

gcry_error_t stretch_and_check_pass(const char *pass, size_t passlen,
                                    struct pws3_header *pro,
                                    struct safe_sec    *sec)
{
    gcry_error_t err;

    stretch_key(pass, passlen, pro, sec->pprime);

    uint8_t hkey[SHA256_SIZE];
    err = sha256_md(sec->pprime, hkey, SHA256_SIZE);
    if (err != GPG_ERR_NO_ERROR) {
        goto exitfn;
    }
    if (memcmp(pro->h_pprime, hkey, SHA256_SIZE) != 0) {
        err = gcry_err_code_from_errno(EINVAL);
        goto exitfn;
    }

    /* Extract random keys K and L. */
    err = extract_random_key(sec->pprime, pro->b[0], pro->b[1], sec->rand_k);
    if (err != GPG_ERR_NO_ERROR) {
        goto exitfn;
    }

    err = extract_random_key(sec->pprime, pro->b[2], pro->b[3], sec->rand_l);
exitfn:
    return err;
}
