#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

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

int  init_decrypt_ctx(struct crypto_ctx *ctx, struct pws3_header *pro,
                      struct safe_sec *sec);
void term_decrypt_ctx(struct crypto_ctx *ctx);
void dump_bytes(FILE *f, uint8_t *ptr, unsigned cnt);
void dump_db_field(FILE *f, struct field *fld);
void dump_hdr_field(FILE *f, struct field *fld);
void dump_prologue(FILE *f, struct pws3_header *pro);

extern gcry_error_t stretch_and_check_pass(const char *pass, size_t passlen,
                                           struct pws3_header *pro,
                                           struct safe_sec    *sec);
extern gcry_error_t extract_random_key(const uint8_t *stretchkey,
                                       const uint8_t *fst, const uint8_t *snd,
                                       uint8_t *randkey);
