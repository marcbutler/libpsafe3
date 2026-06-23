#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cstddef>
#include <cstdint>
#include <span>

class MappedMemory {
public:
    ~MappedMemory();
    MappedMemory(MappedMemory &&) noexcept;
    MappedMemory &operator=(MappedMemory &&) noexcept;
    MappedMemory(const MappedMemory &)            = delete;
    MappedMemory &operator=(const MappedMemory &) = delete;

    const std::byte *data() const noexcept;
    size_t           size() const noexcept;
    std::span<const std::byte> span() const noexcept;

private:
    friend class MappedFile;
    MappedMemory(uintptr_t base, size_t size) noexcept;
    uintptr_t base_;
    size_t    size_;
};
