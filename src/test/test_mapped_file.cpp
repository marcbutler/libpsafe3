// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cassert>
#include <cerrno>
#include <cstring>

#include "mapped.h"

using psafe3::MappedFile;

static const char TEST_PSAFE3[] = TEST_DATA_DIR "/test.psafe3";
static const size_t TEST_PSAFE3_SIZE = 824;

// PWS3 magic bytes at offset 0
static const unsigned char PWS3_MAGIC[] = {'P', 'W', 'S', '3'};

static void test_open_valid()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    auto &mf = result.value();
    assert(mf.base() != 0);
    assert(mf.size() == TEST_PSAFE3_SIZE);
}

static void test_file_contents()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    const unsigned char *p = (const unsigned char *)result.value().base();
    assert(memcmp(p, PWS3_MAGIC, sizeof(PWS3_MAGIC)) == 0);
}

static void test_open_nonexistent()
{
    auto result = MappedFile::open("/nonexistent/path/file.psafe3", psafe3::MemoryAccess::Read);
    assert(!result.has_value());
    assert(result.error() == std::error_code(ENOENT, std::system_category()));
}

static void test_close()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    result.value().close();

    assert(result.value().base() == 0);
    assert(result.value().size() == 0);
}

static void test_close_idempotent()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    result.value().close();
    result.value().close();
}

static void test_move_ctor()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    uintptr_t base = result.value().base();
    size_t    size = result.value().size();

    MappedFile moved(std::move(result.value()));

    assert(moved.base() == base);
    assert(moved.size() == size);
    assert(result.value().base() == 0);
    assert(result.value().size() == 0);
}

static void test_move_assign()
{
    auto r1 = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    auto r2 = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(r1.has_value());
    assert(r2.has_value());

    uintptr_t base = r2.value().base();
    size_t    size = r2.value().size();

    r1.value() = std::move(r2.value());

    assert(r1.value().base() == base);
    assert(r1.value().size() == size);
    assert(r2.value().base() == 0);
    assert(r2.value().size() == 0);
}

static void test_detach()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    uintptr_t orig_base = result.value().base();
    size_t    orig_size = result.value().size();

    psafe3::MappedMemory region = result.value().detach();

    // MappedFile is now closed
    assert(result.value().base() == 0);
    assert(result.value().size() == 0);

    // region owns the original mapping
    assert(region.size() == orig_size);
    assert(reinterpret_cast<uintptr_t>(region.data()) == orig_base);

    // content is accessible via span()
    auto s = region.span();
    assert(s.size() == orig_size);
    assert(memcmp(s.data(), PWS3_MAGIC, sizeof(PWS3_MAGIC)) == 0);
}

static void test_slice()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    auto &mf = result.value();

    // slice at offset 0 matches PWS3 magic
    auto magic = mf.slice(0, sizeof(PWS3_MAGIC));
    assert(magic.size() == sizeof(PWS3_MAGIC));
    assert(memcmp(magic.data(), PWS3_MAGIC, sizeof(PWS3_MAGIC)) == 0);

    // slice at non-zero offset
    auto mid = mf.slice(4, 32);
    assert(mid.size() == 32);
    assert(mid.data() == reinterpret_cast<const std::byte *>(mf.base()) + 4);

    // zero-length slice
    auto empty = mf.slice(0, 0);
    assert(empty.size() == 0);
}

static void test_move_assign_self()
{
    auto result = MappedFile::open(TEST_PSAFE3, psafe3::MemoryAccess::Read);
    assert(result.has_value());

    uintptr_t base = result.value().base();
    size_t    size = result.value().size();

    MappedFile &mf = result.value();
    mf = std::move(mf);

    assert(mf.base() == base);
    assert(mf.size() == size);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    test_open_valid();
    test_file_contents();
    test_open_nonexistent();
    test_close();
    test_close_idempotent();
    test_move_ctor();
    test_move_assign();
    test_move_assign_self();
    test_detach();
    test_slice();

    return 0;
}
