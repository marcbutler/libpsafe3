#pragma once
/* Copyright 2013-present Marc Butler <mockbutler@gmail.com> */

#include <gcrypt.h>

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
