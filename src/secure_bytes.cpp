// https://github.com/marcbutler/libpsafe3/LICENSE

#include <new>

#include "secure_bytes.h"

namespace psafe3 {

SecureBytes::SecureBytes(size_t size)
    : data_(gcry_malloc_secure(size))
    , size_(size)
{
    if (!data_) {
        throw std::bad_alloc();
    }
}

SecureBytes::~SecureBytes()
{
    if (data_) {
        gcry_free(data_);
    }
}

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : data_(other.data_)
    , size_(other.size_)
{
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept
{
    if (this != &other) [[likely]] {
        gcry_free(data_);
        data_ = other.data_;
        other.data_ = nullptr;
        size_ = other.size_;
        other.size_ = 0;
    }
    return *this;
}

std::byte* SecureBytes::data() noexcept
{
    return static_cast<std::byte*>(data_);
}

std::byte* SecureBytes::data(size_t offset) noexcept
{
    return static_cast<std::byte*>(data_) + offset;
}

const std::byte* SecureBytes::data() const noexcept
{
    return static_cast<const std::byte*>(data_);
}

const std::byte* SecureBytes::data(size_t offset) const noexcept
{
    return static_cast<const std::byte*>(data_) + offset;
}

size_t SecureBytes::size() const noexcept
{
    return size_;
}

std::span<std::byte> SecureBytes::as_span() noexcept
{
    return { static_cast<std::byte*>(data_), size_ };
}

std::span<const std::byte> SecureBytes::as_span() const noexcept
{
    return { static_cast<const std::byte*>(data_), size_ };
}

std::span<std::byte> SecureBytes::span(size_t offset, size_t len) noexcept
{
    return { static_cast<std::byte*>(data_) + offset, len };
}

std::span<const std::byte> SecureBytes::span(size_t offset, size_t len) const noexcept
{
    return { static_cast<const std::byte*>(data_) + offset, len };
}

} // namespace psafe3
