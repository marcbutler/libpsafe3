#pragma once
/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <cstddef>
#include <cstdint>
#include <expected>
#include <system_error>

class MappedFile {
public:
    static std::expected<MappedFile, std::error_code> open(const char *path);

    ~MappedFile();
    MappedFile(MappedFile &&) noexcept;
    MappedFile &operator=(MappedFile &&) noexcept;
    MappedFile(const MappedFile &)            = delete;
    MappedFile &operator=(const MappedFile &) = delete;

    void      close();
    uintptr_t base() const noexcept;
    size_t    size() const noexcept;

private:
    MappedFile(uintptr_t base, size_t size) noexcept;
    uintptr_t base_;
    size_t    size_;
};
