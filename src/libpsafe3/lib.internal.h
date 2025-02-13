#pragma once
// https://github.com/marcbutler/psafe

#include <assert.h>

#define TWOFISH_SIZE 16 // Bytes
#define SHA256_SIZE 32  // Bytes

// Denote for library internal use only.
#define LIBONLY __attribute__((visibility("hidden")))

#define ASSERTPTR(ptr) assert((ptr) != NULL)
