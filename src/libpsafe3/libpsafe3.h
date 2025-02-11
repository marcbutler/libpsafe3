#pragma once
// https://github.com/marcbutler/psafe

// Twofish cipher block size bytes.
#define TWOFISH_BLOCK_SIZE 16

// SHA-256 size in bytes.
#define SHA256_SIZE 32

int libpsafe3_init();
int libpsafe3_term();
