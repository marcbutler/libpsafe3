// https://github.com/marcbutler/libpsafe3/LICENSE

#include <sys/mman.h>
#include <utility>

#include "mapped_memory.h"

MappedMemory::MappedMemory(uintptr_t base, size_t size) noexcept
    : base_(base)
    , size_(size)
{
}

MappedMemory::MappedMemory(MappedMemory&& other) noexcept
    : base_(other.base_)
    , size_(other.size_)
{
    other.base_ = 0;
    other.size_ = 0;
}

MappedMemory& MappedMemory::operator=(MappedMemory&& other) noexcept
{
    MappedMemory tmp(std::move(other));
    std::swap(base_, tmp.base_);
    std::swap(size_, tmp.size_);
    return *this;
}

MappedMemory::~MappedMemory()
{
    if (base_ != 0)
        munmap(reinterpret_cast<void*>(base_), size_);
}

const std::byte* MappedMemory::data() const noexcept
{
    return reinterpret_cast<const std::byte*>(base_);
}

size_t MappedMemory::size() const noexcept { return size_; }

std::span<const std::byte> MappedMemory::span() const noexcept
{
    return { data(), size_ };
}
