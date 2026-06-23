// https://github.com/marcbutler/libpsafe3/LICENSE

#include <bit>
#include <cassert>
#include <cstddef>

#include "utility.h"

using namespace psafe3;

static void test_load_u8()
{
    std::byte b{0x42};
    std::span<const std::byte, 1> s{&b, 1};
    assert((load<std::endian::little>(s)) == 0x42u);
    assert((load<std::endian::big>(s)) == 0x42u);
}

static void test_load_u16_le()
{
    // little-endian: LSB first. {0x01, 0x00} → 1
    std::byte mem[] = {std::byte{0x01}, std::byte{0x00}};
    std::span<const std::byte, 2> s{mem};
    assert((load<std::endian::little>(s)) == 1u);

    // {0xFE, 0xFF} → 0xFFFE = 65534
    std::byte mem2[] = {std::byte{0xFE}, std::byte{0xFF}};
    std::span<const std::byte, 2> s2{mem2};
    assert((load<std::endian::little>(s2)) == 0xFFFEu);
}

static void test_load_u16_be()
{
    // big-endian: MSB first. {0x00, 0x01} → 1
    std::byte mem[] = {std::byte{0x00}, std::byte{0x01}};
    std::span<const std::byte, 2> s{mem};
    assert((load<std::endian::big>(s)) == 1u);

    // {0xFF, 0xFE} → 0xFFFE = 65534
    std::byte mem2[] = {std::byte{0xFF}, std::byte{0xFE}};
    std::span<const std::byte, 2> s2{mem2};
    assert((load<std::endian::big>(s2)) == 0xFFFEu);
}

static void test_load_u32_le()
{
    // {0x01, 0x00, 0x00, 0x00} → 1
    std::byte mem[] = {std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    std::span<const std::byte, 4> s{mem};
    assert((load<std::endian::little>(s)) == 1u);

    // {0xFE, 0xFF, 0xFF, 0xFF} → UINT32_MAX - 1
    std::byte mem2[] = {std::byte{0xFE}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};
    std::span<const std::byte, 4> s2{mem2};
    assert((load<std::endian::little>(s2)) == 0xFFFFFFFEu);

    // {0x78, 0x56, 0x34, 0x12} → 0x12345678
    std::byte mem3[] = {std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12}};
    std::span<const std::byte, 4> s3{mem3};
    assert((load<std::endian::little>(s3)) == 0x12345678u);
}

static void test_load_u32_be()
{
    // {0x00, 0x00, 0x00, 0x01} → 1
    std::byte mem[] = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
    std::span<const std::byte, 4> s{mem};
    assert((load<std::endian::big>(s)) == 1u);

    // {0xFF, 0xFF, 0xFF, 0xFE} → UINT32_MAX - 1
    std::byte mem2[] = {std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFE}};
    std::span<const std::byte, 4> s2{mem2};
    assert((load<std::endian::big>(s2)) == 0xFFFFFFFEu);

    // {0x12, 0x34, 0x56, 0x78} → 0x12345678
    std::byte mem3[] = {std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};
    std::span<const std::byte, 4> s3{mem3};
    assert((load<std::endian::big>(s3)) == 0x12345678u);
}

static void test_load_u64_le()
{
    // {0x01, 0x00, ..., 0x00} → 1
    std::byte mem[] = {
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    std::span<const std::byte, 8> s{mem};
    assert((load<std::endian::little>(s)) == 1ull);

    // {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01} → 0x0123456789ABCDEF
    std::byte mem2[] = {
        std::byte{0xEF}, std::byte{0xCD}, std::byte{0xAB}, std::byte{0x89},
        std::byte{0x67}, std::byte{0x45}, std::byte{0x23}, std::byte{0x01},
    };
    std::span<const std::byte, 8> s2{mem2};
    assert((load<std::endian::little>(s2)) == 0x0123456789ABCDEFull);
}

static void test_load_u64_be()
{
    // {0x00, ..., 0x00, 0x01} → 1
    std::byte mem[] = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };
    std::span<const std::byte, 8> s{mem};
    assert((load<std::endian::big>(s)) == 1ull);

    // {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF} → 0x0123456789ABCDEF
    std::byte mem2[] = {
        std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
        std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
    };
    std::span<const std::byte, 8> s2{mem2};
    assert((load<std::endian::big>(s2)) == 0x0123456789ABCDEFull);
}

static void test_load_zero()
{
    std::byte mem[] = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    std::span<const std::byte, 4> s{mem};
    assert((load<std::endian::little>(s)) == 0u);
    assert((load<std::endian::big>(s)) == 0u);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    test_load_u8();
    test_load_u16_le();
    test_load_u16_be();
    test_load_u32_le();
    test_load_u32_be();
    test_load_u64_le();
    test_load_u64_be();
    test_load_zero();

    return 0;
}
