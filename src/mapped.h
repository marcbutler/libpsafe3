#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <system_error>

#include <sys/mman.h>

namespace psafe3 {

enum class MemoryAccess : int {
    None = PROT_NONE,
    Read = PROT_READ,
    Write = PROT_WRITE,
    Exec = PROT_EXEC
};

class MappedFile;

class MappedMemory {
public:
    ~MappedMemory();
    MappedMemory(MappedMemory&&) noexcept;
    MappedMemory& operator=(MappedMemory&&) noexcept;
    MappedMemory(const MappedMemory&) = delete;
    MappedMemory& operator=(const MappedMemory&) = delete;

    MemoryAccess access() const noexcept { return MemoryAccess(access_); }
    const std::byte* data() const noexcept;
    size_t size() const noexcept;
    std::span<const std::byte> span() const noexcept;

private:
    friend class MappedFile;
    MappedMemory(uintptr_t base, size_t size, MemoryAccess access) noexcept;
    uintptr_t base_;
    size_t size_;
    int access_;
};

class MappedFile {
public:
    static std::expected<MappedFile, std::error_code> open(const std::filesystem::path& path, MemoryAccess access);

    ~MappedFile();
    MappedFile(MappedFile&&) noexcept;
    MappedFile& operator=(MappedFile&&) noexcept;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    void close();
    MappedMemory detach() noexcept;
    uintptr_t base() const noexcept;
    size_t size() const noexcept;
    std::span<const std::byte> slice(size_t offset, size_t length) const noexcept;

    template <size_t N>
    std::span<const std::byte, N> slice(size_t offset) const noexcept
    {
        assert(offset + N <= size_);
        return std::span<const std::byte, N>(
            reinterpret_cast<const std::byte*>(base_) + offset, N);
    }

private:
    MappedFile(uintptr_t base, size_t size, MemoryAccess access) noexcept;
    uintptr_t base_;
    size_t size_;
    MemoryAccess access_;
};

} // namespace psafe3
