#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <cstddef>
#include <expected>
#include <span>
#include <system_error>

#include <gcrypt.h>

#include "common.h"
#include "error.h"
#include "secure_bytes.h"

#define CRYPTO_OK(err) ((err) == GPG_ERR_NO_ERROR)

#define CRYPTO_FAIL(err) ((err) != GPG_ERR_NO_ERROR)

psafe3_err crypto_init();
psafe3_err crypto_term();

psafe3_err crypto_stretch_key(const unsigned char* pass, size_t passlen,
    const sha256_hash salt, long iterations,
    sha256_hash stretched_key);

psafe3_err crypto_sha256md(const unsigned char* in, unsigned char* out,
    size_t len);

void* crypto_secure_malloc(size_t size);
void crypto_secure_free(void* ptr);

namespace psafe3 {

static constexpr size_t SHA256_SIZE = 32;

std::expected<SecureBytes, std::error_code>
stretch_key(std::span<const std::byte> pass,
    std::span<const std::byte, SHA256_SIZE> salt,
    uint32_t iterations);

std::expected<std::array<std::byte, SHA256_SIZE>, std::error_code>
sha256(std::span<const std::byte> data);

} // namespace psafe3
