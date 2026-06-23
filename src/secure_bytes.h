#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cstddef>
#include <span>

#include <gcrypt.h>

namespace psafe3 {

class SecureBytes {
public:
    explicit SecureBytes(size_t size);
    ~SecureBytes();

    SecureBytes(SecureBytes &&) noexcept;
    SecureBytes &operator=(SecureBytes &&) noexcept;
    SecureBytes(const SecureBytes &)            = delete;
    SecureBytes &operator=(const SecureBytes &) = delete;

    std::byte             *data() noexcept;
    const std::byte       *data() const noexcept;
    size_t                 size() const noexcept;
    std::span<std::byte>       span() noexcept;
    std::span<const std::byte> span() const noexcept;

private:
    void  *data_;
    size_t size_;
};

} // namespace psafe3
