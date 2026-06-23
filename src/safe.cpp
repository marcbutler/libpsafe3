// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <cmath>
#include <expected>
#include <sys/types.h>
#include <system_error>

#include "common.h"
#include "crypto.h"
#include "error.h"
#include "mapped_file.h"
#include "safe.h"
#include "secure_bytes.h"
#include "util.h"
#include "utility.h"

// File format.
//
// OFF SZ NAME
//   0  4 MAGIC
//   4 32 SALT
//  36  4 ITER
//  40 32 H(P')
//  72 16 B1
//  88 16 B2
// 104 16 B3
// 120 16 B4
// 136 16 IV
//
//  Field
//   0  4 LENGTH
//   4  1 TYPE
//   5  * FIELD DATA

namespace
{
enum PROLOGUE : unsigned int {
    MAGIC_OFFSET = 0,
    MAGIC_SIZE = 4,
    SALT_OFFSET = MAGIC_OFFSET + MAGIC_SIZE,
    SALT_SIZE = 32,
    ITER_OFFSET = SALT_OFFSET + SALT_SIZE,
    ITER_SIZE = 4,
    PASS_HASH_OFFSET = ITER_OFFSET + ITER_SIZE,
    PASS_HASH_SIZE = 32,
    OFFSET_B1 = PASS_HASH_OFFSET + PASS_HASH_SIZE,
    B_SIZE = 16,
    OFFSET_B2 = OFFSET_B1 + B_SIZE,
    OFFSET_B3 = OFFSET_B2 + B_SIZE,
    OFFSET_B4 = OFFSET_B3 + B_SIZE,
    OFFSET_IV = OFFSET_B4 + B_SIZE,
    IV_SIZE = 16,
    PROLOGUE_SIZE = OFFSET_IV + IV_SIZE
};

static const std::array<std::byte, MAGIC_SIZE> MAGIC = {
    std::byte{'P'},
    std::byte{'W'},
    std::byte{'S'},
    std::byte{'3'},
};

static const std::array<std::byte, 16> DBEND = {
    std::byte{'P'}, std::byte{'W'}, std::byte{'S'}, std::byte{'3'},
    std::byte{'-'}, std::byte{'E'}, std::byte{'O'}, std::byte{'F'},
    std::byte{'P'}, std::byte{'W'}, std::byte{'S'}, std::byte{'3'},
    std::byte{'-'}, std::byte{'E'}, std::byte{'O'}, std::byte{'F'},
};

} // namespace

psafe3_err safe_load_prologue(int fd, unsigned char *prologue)
{
    off_t ret;
    ssize_t  nread;

    assert_fd(fd);
    assert_ptr(prologue);

    ret = lseek(fd, 0, SEEK_SET);
    if (ret == -1) {
        return gpg_err_code_from_errno(errno);
    }

    nread = read(fd, prologue, PROLOGUE_SIZE);
    if (nread == -1) {
        return gpg_err_code_from_errno(errno);
    }
    if (nread != PROLOGUE_SIZE) {
        return gpg_err_code_from_errno(EIO);
    }

    if (memcmp(prologue + MAGIC_OFFSET, MAGIC.data(), MAGIC.size()) != 0) {
        return gpg_err_code_from_errno(EINVAL);
    }

    return GPG_ERR_NO_ERROR;
}

unsigned char const *safe_salt(struct safe *s)
{
    return (unsigned char const *)s->file_image + SALT_OFFSET;
}

uint32_t safe_iter(struct safe *s)
{
    unsigned char const *b = (unsigned char const *)s->file_image + ITER_OFFSET;
    uint32_t count = b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24);
    return count;
}

unsigned char const *safe_pass_hash(struct safe *s)
{
    return (unsigned char const *)s->file_image + PASS_HASH_OFFSET;
}

unsigned char const *safe_b(struct safe *s, unsigned i)
{
    assert(i < 4);
    static const size_t OFFSET_sets[4] = {
        OFFSET_B1,
        OFFSET_B2,
        OFFSET_B3,
        OFFSET_B4,
    };
    return (unsigned char const *)s->file_image + OFFSET_sets[i];
}

unsigned char const *safe_iv(struct safe *s)
{
    return (unsigned char const *)s->file_image + OFFSET_IV;
}

namespace psafe3
{
std::expected<Safe, std::error_code>
Safe::load(const std::filesystem::path &path,
           const std::vector<std::byte> pass_phrase)
{
    auto mapped_file = MappedFile::open(path.c_str());
    if (!mapped_file) {
        return std::unexpected(mapped_file.error());
    }
    auto &contents = mapped_file.value();
    // TODO Check if file size is < minimum viable safe size.
    if (MAGIC != contents.slice<MAGIC.size()>(PROLOGUE::MAGIC_OFFSET)) {
        return std::unexpected(psafe3::Error::invalid_magic);
    }

    auto iter = psafe3::load<std::endian::little>(contents.slice<PROLOGUE::ITER_SIZE>(PROLOGUE::ITER_OFFSET));
    auto stretch_result = psafe3::stretch_key(pass_phrase, contents.slice<PROLOGUE::SALT_SIZE>(PROLOGUE::SALT_OFFSET), iter);
    if (!stretch_result) [[unlikely]] {
        return std::unexpected(stretch_result.error());
    }
    SecureBytes key = std::move(stretch_result.value());
    auto key_hash_calc = psafe3::sha256(key.span());
    if (!key_hash_calc) [[unlikely]] {
        return std::unexpected(key_hash_calc.error());
    }
    auto key_hash = key_hash_calc.value();
    if (key_hash != contents.slice<PROLOGUE::PASS_HASH_SIZE>(PROLOGUE::PASS_HASH_OFFSET))
    {
        return std::unexpected(psafe3::Error::invalid_password);
    }

    return Safe(contents.detach());
}
} // namespace psafe3
