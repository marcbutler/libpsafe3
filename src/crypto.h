#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <cstddef>
#include <expected>
#include <span>
#include <system_error>

#include <gcrypt.h>

#include "error.h"
#include "secure_bytes.h"

namespace psafe3 {

static constexpr size_t SHA256_SIZE = 32;

std::expected<SecureBytes, std::error_code>
stretch_key(std::span<const std::byte> pass,
    std::span<const std::byte, SHA256_SIZE> salt,
    uint32_t iterations);

std::expected<std::array<std::byte, SHA256_SIZE>, std::error_code>
sha256(std::span<const std::byte> data);

class SHA256HMA {
public:
    ~SHA256HMA();
    SHA256HMA(SHA256HMA&&) noexcept;
    SHA256HMA& operator=(SHA256HMA&&) noexcept;
    SHA256HMA(const SHA256HMA&) = delete;
    SHA256HMA& operator=(const SHA256HMA&) = delete;

    static std::expected<SHA256HMA, std::error_code> create(std::span<const std::byte> key);
    void write(std::span<const std::byte> data);
    std::expected<std::array<std::byte, SHA256_SIZE>, std::error_code> finish();

private:
    gcry_md_hd_t hd_{};
    explicit SHA256HMA(gcry_md_hd_t hd) : hd_(hd) { }
};

} // namespace psafe3
