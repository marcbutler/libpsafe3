#pragma once
// https://github.com/marcbutler/psafe

#include <assert.h>

#define TWOFISH_SIZE 16 // Bytes
#define SHA256_SIZE 32  // Bytes

// Denote for library internal use only.
#define INTERNAL __attribute__((visibility("hidden")))

#define ASSERTPTR(ptr) assert((ptr) != NULL)

#define KIB(n) ((n) * 1024)
#define MIB(n) ((n) * 1048576)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

