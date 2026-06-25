#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cstddef>
#include <memory>
#include <span>

#include <gcrypt.h>

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
        return *(reinterpret_cast<std::byte*>(data_) + offset);
    }

    size_t size() const noexcept;

    std::span<std::byte> as_span() noexcept;
    std::span<const std::byte> as_span() const noexcept;
    std::span<std::byte> span(size_t offset, size_t len) noexcept;
    std::span<const std::byte> span(size_t offset, size_t len) const noexcept;

    template <size_t N>
    std::span<const std::byte, N> span(size_t offset)
    {
        return std::span<const std::byte, N>(data(offset), N);
    }

private:
    void* data_;
    size_t size_;
};



} // namespace psafe3
