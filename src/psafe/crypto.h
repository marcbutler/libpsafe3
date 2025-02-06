#pragma once

#include <gcrypt.h>

/* Twofish cipher block size bytes. */
#define TWOFISH_BLOCK_SIZE 16

/* SHA-256 size in bytes. */
#define SHA256_SIZE 32


/* Deprecate / rename. */
void gcrypt_fatal(gcry_error_t err);

void crypto_init(size_t secmem_pool_size);
void crypto_term(void);
