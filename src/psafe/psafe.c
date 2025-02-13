#include <assert.h>
#include <errno.h>
#include <gcrypt.h>
#include <getopt.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include "libpsafe3/lib.internal.h"
#include "libpsafe3/util.h"

#include "psafe.h"
#include "pws3.h"

static void gcrypt_fatal(gcry_error_t err)
{
    fwprintf(stderr, L"gcrypt error %s/%s\n", gcry_strsource(err),
             gcry_strerror(err));
    exit(EXIT_FAILURE);
}

LIBONLY void stretch_key(const char *pass, size_t passlen,
                         const struct pws3_header *pro, uint8_t *skey)
{
    gcry_error_t gerr;
    gcry_md_hd_t sha256;
    gerr = gcry_md_open(&sha256, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (gerr != GPG_ERR_NO_ERROR) {
        gcrypt_fatal(gerr);
    }

    gcry_md_write(sha256, pass, passlen);
    gcry_md_write(sha256, pro->salt, 32);
    memmove(skey, gcry_md_read(sha256, 0), 32);

    uint32_t iter = pro->iter;
    while (iter-- > 0) {
        gcry_md_reset(sha256);
        gcry_md_write(sha256, skey, 32);
        memmove(skey, gcry_md_read(sha256, 0), 32);
    }
    gcry_md_close(sha256);
}

/*
 * Run SHA-256 on a 32 byte block.
 */
void sha256_block32(const uint8_t *in, uint8_t *out)
{
    gcry_md_hd_t hd;
    gcry_error_t err;
    err = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (err != GPG_ERR_NO_ERROR) {
        gcrypt_fatal(err);
    }
    gcry_md_write(hd, in, SHA256_SIZE);
    err = gcry_md_final(hd);
    if (err != GPG_ERR_NO_ERROR) {
        gcrypt_fatal(err);
    }
    memmove(out, gcry_md_read(hd, 0), SHA256_SIZE);
    gcry_md_close(hd);
}

gcry_error_t extract_random_key(const uint8_t *stretchkey, const uint8_t *fst,
                                const uint8_t *snd, uint8_t *randkey)
{
    /*
     *  Extract the random key generated by PasswordSafe.
     */
    gcry_error_t gerr;
    gcry_cipher_hd_t hd;
    gerr = gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB,
                            GCRY_CIPHER_SECURE);
    if (gerr != GPG_ERR_NO_ERROR) {
        return gerr;
    }
    gerr = gcry_cipher_setkey(hd, stretchkey, 32);
    if (gerr != GPG_ERR_NO_ERROR) {
        return gerr;
    }
    gcry_cipher_decrypt(hd, randkey, 16, fst, 16);
    gcry_cipher_reset(hd);
    gcry_cipher_decrypt(hd, randkey + 16, 16, snd, 16);
    gcry_cipher_close(hd);
    return GPG_ERR_NO_ERROR;
}

void print_time(uint8_t *val)
{
    struct tm *lt;
    time_t time;
    time = load_le32(val);
    lt = gmtime(&time);
    wprintf(L"%d-%d-%d %02d:%02d:%02d", 1900 + lt->tm_year, lt->tm_mon,
            lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
}

void printhex(FILE *f, uint8_t *ptr, unsigned cnt)
{
    unsigned i;
    for (i = 0; i < cnt; i++) {
        fwprintf(f, L"%02x", *ptr++);
    }
}

void print_uuid(uint8_t *uuid)
{
    printhex(stdout, uuid, 4);
    putwc('-', stdout);
    printhex(stdout, uuid + 4, 2);
    putwc('-', stdout);
    printhex(stdout, uuid + 6, 2);
    putwc('-', stdout);
    printhex(stdout, uuid + 8, 2);
    putwc('-', stdout);
    printhex(stdout, uuid + 10, 6);
}

/* Print out utf-8 string. */
void pws(FILE *f, uint8_t *bp, size_t len)
{
    mbstate_t state;
    memset(&state, 0, sizeof(state));
    wchar_t *tmp;
    tmp = malloc((len + 1) * sizeof(wchar_t));
    size_t n;
    const char *ptr = (const char *)bp;
    n = mbsrtowcs(tmp, &ptr, len, &state);
    tmp[n] = L'\0';
    fputws(tmp, f);
    free(tmp);
}

void hd_print(FILE *f, struct field *fld)
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

void db_print(FILE *f, struct field *fld)
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

    ASSERTPTR(ctx);
    ASSERTPTR(pro);
    ASSERTPTR(sec);

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

    gerr = gcry_md_setkey(ctx->hmac, sec->rand_l, 32);
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

void print_prologue(FILE *f, struct pws3_header *pro)
{
    int i;
#define EOL() fputwc('\n', f)
    fputws(L"SALT   ", f);
    printhex(f, pro->salt, 32);
    EOL();
    fwprintf(f, L"ITER   %" PRIu32 L"\n", pro->iter);
    fputws(L"H(P')  ", f);
    printhex(f, pro->h_pprime, 32);
    EOL();
    for (i = 0; i < 4; i++) {
        fwprintf(f, L"B%d     ", i);
        printhex(f, pro->b[i], 16);
        EOL();
    }
    fputws(L"IV     ", f);
    printhex(f, pro->iv, 16);
    EOL();
#undef EOL
}

/// @brief
/// @param pass Password must not be null.
/// @param passlen Password length in bytes. Behavior is undefined if the length
/// is zero.
/// @param pro File header block.
/// @param sec Security context.
/// @retval -EINVAL Invalid password.
gcry_error_t stretch_and_check_pass(const char *pass, size_t passlen,
                                    struct pws3_header *pro,
                                    struct safe_sec *sec)
{
    gcry_error_t err;
    stretch_key(pass, passlen, pro, sec->pprime);

    uint8_t hkey[SHA256_SIZE];
    sha256_block32(sec->pprime, hkey);
    if (memcmp(pro->h_pprime, hkey, SHA256_SIZE) != 0) {
        err = gcry_err_code_from_errno(EINVAL);
        goto exitfn;
    }
    
    // Extract random keys K and L.
    err = extract_random_key(sec->pprime, pro->b[0], pro->b[1], sec->rand_k);
    if (err != GPG_ERR_NO_ERROR) {
        goto exitfn;
    }
    err = extract_random_key(sec->pprime, pro->b[2], pro->b[3], sec->rand_l);
exitfn:
    return err;
}
