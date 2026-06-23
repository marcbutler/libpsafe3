// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>
#include <system_error>
#include <unistd.h>

#include "mapped_file.h"
#include "mapped_memory.h"
#include "util.h"

MappedFile::MappedFile(uintptr_t base, size_t size) noexcept
    : base_(base)
    , size_(size)
{
}

MappedFile::MappedFile(MappedFile&& other) noexcept
    : base_(other.base_)
    , size_(other.size_)
{
    other.base_ = 0;
    other.size_ = 0;
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept
{
    MappedFile tmp(std::move(other));
    std::swap(base_, tmp.base_);
    std::swap(size_, tmp.size_);
    return *this;
}

MappedFile::~MappedFile()
{
    try {
        close();
    } catch (const std::system_error& e) {
#ifdef NDEBUG
        syslog(LOG_ERR, "munmap failed: %s", e.what());
#else
        crash();
#endif
    }
}

void MappedFile::close()
{
    if (base_ == 0)
        return;
    if (munmap((void*)base_, size_) != 0)
        throw std::system_error(errno, std::system_category());
    base_ = 0;
    size_ = 0;
}

MappedMemory MappedFile::detach() noexcept
{
    MappedMemory region(base_, size_);
    base_ = 0;
    size_ = 0;
    return region;
}

uintptr_t MappedFile::base() const noexcept { return base_; }
size_t MappedFile::size() const noexcept { return size_; }

std::span<const std::byte> MappedFile::slice(size_t offset, size_t length) const noexcept
{
    assert(offset + length <= size_);
    return { reinterpret_cast<const std::byte*>(base_) + offset, length };
}

std::expected<MappedFile, std::error_code> MappedFile::open(const char* path)
{
    int fd = ::open(path, O_RDONLY);
    if (fd < 0)
        return std::unexpected(std::error_code(errno, std::system_category()));

    struct stat st;
    if (fstat(fd, &st) < 0) {
        auto err = std::error_code(errno, std::system_category());
        ::close(fd);
        return std::unexpected(err);
    }

    void* ptr = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (ptr == MAP_FAILED)
        return std::unexpected(std::error_code(errno, std::system_category()));

    return MappedFile((uintptr_t)ptr, (size_t)st.st_size);
}
