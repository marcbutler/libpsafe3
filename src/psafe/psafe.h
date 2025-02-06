#pragma once

#include <gcrypt.h>

#include "pws3.h"

/* Field header. */
struct field {
    uint32_t len;
    uint8_t  type;
    uint8_t  val[];
} __attribute__((packed));

/* Secure safe information. */
struct safe_sec {
    uint8_t pprime[32];
    uint8_t rand_k[32];
    uint8_t rand_l[32];
};

/* Cryptographic context */
struct crypto_ctx {
    gcry_error_t     gerr;
    gcry_cipher_hd_t cipher;
    gcry_md_hd_t     hmac;
};

int stretch_and_check_pass(const char *pass, size_t passlen,
                           struct pws3_header *pro, struct safe_sec *sec);
int init_decrypt_ctx(struct crypto_ctx *ctx, struct pws3_header *pro,
                     struct safe_sec *sec);
void term_decrypt_ctx(struct crypto_ctx *ctx);
void printhex(FILE *f, uint8_t *ptr, unsigned cnt);
void db_print(FILE *f, struct field *fld);
void hd_print(FILE *f, struct field *fld);
void print_prologue(FILE *f, struct pws3_header *pro);
