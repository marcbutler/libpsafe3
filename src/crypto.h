#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <cstddef>
#include <cstdio>
#include <expected>
#include <span>
#include <system_error>

#include <gcrypt.h>

#include "error.h"

namespace psafe3 {

class SecureBytes {
public:
    explicit SecureBytes(size_t size);
    ~SecureBytes();

    SecureBytes(SecureBytes&&) noexcept;
    SecureBytes& operator=(SecureBytes&&) noexcept;
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    std::byte* data() noexcept;
    std::byte* data(size_t offset) noexcept;
    const std::byte* data() const noexcept;
    const std::byte* data(size_t offset) const noexcept;

    std::byte byte(size_t offset) const noexcept
    {
        return *(reinterpret_cast<const std::byte*>(data_) + offset);
    }

    size_t size() const noexcept;

    std::span<std::byte> as_span() noexcept;
    std::span<const std::byte> as_span() const noexcept;
    std::span<std::byte> span(size_t offset, size_t len) noexcept;
    std::span<const std::byte> span(size_t offset, size_t len) const noexcept;

    template <size_t N>
    std::span<const std::byte, N> span(size_t offset) const
    {
        return std::span<const std::byte, N>(data(offset), N);
    }

private:
    void* data_;
    size_t size_;
};

static constexpr size_t SHA256_SIZE = 32;

std::expected<SecureBytes, std::error_code>
stretch_key(std::span<const std::byte> pass,
    std::span<const std::byte, SHA256_SIZE> salt,
    uint32_t iterations);

std::expected<std::array<std::byte, SHA256_SIZE>, std::error_code>
sha256(std::span<const std::byte> data);

// SHA256 Hashed Message Authentication Code Generator
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
