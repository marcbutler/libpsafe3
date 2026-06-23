#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

#include "mapped_memory.h"

class MappedFile {
public:
    static std::expected<MappedFile, std::error_code> open(const char *path);

    ~MappedFile();
    MappedFile(MappedFile &&) noexcept;
    MappedFile &operator=(MappedFile &&) noexcept;
    MappedFile(const MappedFile &)            = delete;
    MappedFile &operator=(const MappedFile &) = delete;

    void               close();
    MappedMemory detach() noexcept;
    uintptr_t          base() const noexcept;
    size_t             size() const noexcept;
    std::span<const std::byte> slice(size_t offset, size_t length) const noexcept;

    template <size_t N>
    std::span<const std::byte, N> slice(size_t offset) const noexcept
    {
        assert(offset + N <= size_);
        return std::span<const std::byte, N>(
            reinterpret_cast<const std::byte *>(base_) + offset, N);
    }

private:
    MappedFile(uintptr_t base, size_t size) noexcept;
    uintptr_t base_;
    size_t    size_;
};
