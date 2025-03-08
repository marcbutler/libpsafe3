#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gcrypt.h>
#include <gpg-error.h>

#include <psafe3.h>

/* SHA-256 hash code size in bytes. */
#define SHA256_BYTES 32
typedef unsigned char sha256_hash[SHA256_BYTES];

/* TWOFISH block size in bytes. */
#define TWOFISH_BYTES 16
typedef unsigned char twofish_block[TWOFISH_BYTES];

