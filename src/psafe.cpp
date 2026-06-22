/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <errno.h>
#include <gcrypt.h>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <locale.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include "psafe.h"
#include "pws3.h"
#include "util.h"

static void gcrypt_fatal(gcry_error_t err)
{
    std::wcerr << L"gcrypt error " << widen(gcry_strsource(err))
               << L"/" << widen(gcry_strerror(err)) << L'\n';
    exit(EXIT_FAILURE);
}

/*
 * Perform hash based stretching on the provided password.
 *
 * http://www.schneier.com/paper-low-entropy.pdf
 */
INTERNAL gcry_error_t stretch_key(const char *pass, size_t passlen,
                                  const struct pws3_header *pro, uint8_t *skey)
{
    gcry_error_t  err;
    gcry_md_hd_t  sha256;
    unsigned char tmp[SHA256_SIZE];

    err = gcry_md_open(&sha256, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    gcry_md_write(sha256, pass, passlen);
    gcry_md_write(sha256, pro->salt, SHA256_SIZE);
    memmove(tmp, gcry_md_read(sha256, 0), SHA256_SIZE);

    uint32_t iter = pro->iter;
    assert(iter > 0);
    while (iter-- > 0) {
        gcry_md_reset(sha256);
        gcry_md_write(sha256, tmp, SHA256_SIZE);
        memmove(tmp, gcry_md_read(sha256, 0), SHA256_SIZE);
    }

    memmove(skey, gcry_md_read(sha256, 0), SHA256_SIZE);
    gcry_md_close(sha256);
    return GPG_ERR_NO_ERROR;
}

/*
 * Compute the SHA256 message digest of the input buffer.
 */
INTERNAL gcry_error_t sha256_md(const uint8_t *in, uint8_t *out, size_t len)
{
    gcry_md_hd_t   hd;
    gcry_error_t   err;
    const uint8_t *hash;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (err != GPG_ERR_NO_ERROR) {
        goto exit_with_error;
    }
    gcry_md_write(hd, in, len);
    err = gcry_md_final(hd);
    if (err != GPG_ERR_NO_ERROR) {
        goto exit_with_error;
    }

    hash = gcry_md_read(hd, 0);
    if (hash == NULL) {
        goto exit_with_error;
    }
    memmove(out, hash, SHA256_SIZE);
    gcry_md_close(hd);

exit_with_error:
    return err;
}

/*
 * Decrypt the random key using the stretch key.
 */
INTERNAL gcry_error_t extract_random_key(const uint8_t *stretchkey,
                                         const uint8_t *fst, const uint8_t *snd,
                                         uint8_t *randkey)
{
    gcry_error_t     err;
    gcry_cipher_hd_t hd;

    err = gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB,
                           GCRY_CIPHER_SECURE);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }
    err = gcry_cipher_setkey(hd, stretchkey, SHA256_SIZE);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }
    gcry_cipher_decrypt(hd, randkey, TWOFISH_SIZE, fst, TWOFISH_SIZE);
    gcry_cipher_reset(hd);
    gcry_cipher_decrypt(hd, randkey + TWOFISH_SIZE, TWOFISH_SIZE, snd,
                        TWOFISH_SIZE);
    gcry_cipher_close(hd);
    return GPG_ERR_NO_ERROR;
}

static void print_time(std::wostream &out, uint8_t *val)
{
    struct tm *lt;
    time_t     time;
    time = le32_deserialize(val);
    lt   = gmtime(&time);
    auto fill = out.fill(L'0');
    out << std::dec
        << (1900 + lt->tm_year) << L'-' << lt->tm_mon << L'-' << lt->tm_mday
        << L' '
        << std::setw(2) << lt->tm_hour << L':'
        << std::setw(2) << lt->tm_min  << L':'
        << std::setw(2) << lt->tm_sec;
    out.fill(fill);
}

void dump_bytes(std::wostream &out, const uint8_t *ptr, unsigned cnt)
{
    auto flags = out.flags();
    auto fill  = out.fill(L'0');
    out << std::hex;
    for (unsigned i = 0; i < cnt; i++) {
        out << std::setw(2) << static_cast<unsigned>(*ptr++);
    }
    out.flags(flags);
    out.fill(fill);
}

static void print_uuid(std::wostream &out, uint8_t *uuid)
{
    dump_bytes(out, uuid, 4);
    out << L'-';
    dump_bytes(out, uuid + 4, 2);
    out << L'-';
    dump_bytes(out, uuid + 6, 2);
    out << L'-';
    dump_bytes(out, uuid + 8, 2);
    out << L'-';
    dump_bytes(out, uuid + 10, 6);
}

static void pws(std::wostream &out, uint8_t *bp, size_t len)
{
    mbstate_t state;
    memset(&state, 0, sizeof(state));
    wchar_t    *tmp = (wchar_t *)malloc((len + 1) * sizeof(wchar_t));
    const char *ptr = (const char *)bp;
    size_t      n   = mbsrtowcs(tmp, &ptr, len, &state);
    tmp[n] = L'\0';
    out << tmp;
    free(tmp);
}

void dump_hdr_field(std::wostream &out, struct field *fld)
{
    switch (fld->type) {
    case 0x2 ... 0x3:
    case 0x5 ... 0xb:
    case 0xf ... 0x11:
        pws(out, fld->val, fld->len);
        break;
    case 0x1:
        print_uuid(out, fld->val);
        break;
    case 0x4:
        print_time(out, fld->val);
        break;
    }
}

void dump_db_field(std::wostream &out, struct field *fld)
{
    switch (fld->type) {
    case 0x2 ... 0x6:
    case 0xd ... 0x10:
    case 0x14:
    case 0x16:
        pws(out, fld->val, fld->len);
        break;
    case 0x7 ... 0xa:
    case 0xc:
        print_time(out, fld->val);
        break;
    case 0x1:
        print_uuid(out, fld->val);
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

void dump_prologue(std::wostream &out, struct pws3_header *pro)
{
    out << L"SALT   ";
    dump_bytes(out, pro->salt, 32);
    out << L'\n';
    out << L"ITER   " << pro->iter << L'\n';
    out << L"H(P')  ";
    dump_bytes(out, pro->h_pprime, SHA256_SIZE);
    out << L'\n';
    for (int i = 0; i < 4; i++) {
        out << L"B" << i << L"     ";
        dump_bytes(out, pro->b[i], 16);
        out << L'\n';
    }
    out << L"IV     ";
    dump_bytes(out, pro->iv, 16);
    out << L'\n';
}

gcry_error_t stretch_and_check_pass(const char *pass, size_t passlen,
                                    struct pws3_header *pro,
                                    struct safe_sec    *sec)
{
    gcry_error_t err;
    uint8_t      hkey[SHA256_SIZE];

    err = stretch_key(pass, passlen, pro, sec->pprime);
    if (err != GPG_ERR_NO_ERROR) {
        goto exitfn;
    }

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
