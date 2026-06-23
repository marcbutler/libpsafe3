// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <expected>
#include <ios>
#include <span>
#include <sys/types.h>
#include <system_error>

#include "common.h"
#include "crypto.h"
#include "error.h"
#include "gcrypt.h"
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

namespace {
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
    std::byte { 'P' },
    std::byte { 'W' },
    std::byte { 'S' },
    std::byte { '3' },
};

static const std::array<std::byte, 16> DBEND = {
    std::byte { 'P' },
    std::byte { 'W' },
    std::byte { 'S' },
    std::byte { '3' },
    std::byte { '-' },
    std::byte { 'E' },
    std::byte { 'O' },
    std::byte { 'F' },
    std::byte { 'P' },
    std::byte { 'W' },
    std::byte { 'S' },
    std::byte { '3' },
    std::byte { '-' },
    std::byte { 'E' },
    std::byte { 'O' },
    std::byte { 'F' },
};

} // namespace

psafe3_err safe_load_prologue(int fd, unsigned char* prologue)
{
    off_t ret;
    ssize_t nread;

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

unsigned char const* safe_salt(struct safe* s)
{
    return (unsigned char const*)s->file_image + SALT_OFFSET;
}

uint32_t safe_iter(struct safe* s)
{
    unsigned char const* b = (unsigned char const*)s->file_image + ITER_OFFSET;
    uint32_t count = b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24);
    return count;
}

unsigned char const* safe_pass_hash(struct safe* s)
{
    return (unsigned char const*)s->file_image + PASS_HASH_OFFSET;
}

unsigned char const* safe_b(struct safe* s, unsigned i)
{
    assert(i < 4);
    static const size_t OFFSET_sets[4] = {
        OFFSET_B1,
        OFFSET_B2,
        OFFSET_B3,
        OFFSET_B4,
    };
    return (unsigned char const*)s->file_image + OFFSET_sets[i];
}

unsigned char const* safe_iv(struct safe* s)
{
    return (unsigned char const*)s->file_image + OFFSET_IV;
}

namespace psafe3 {

std::expected<SecureBytes, std::error_code>
extract_random_key(const SecureBytes& pass, std::span<const std::byte, TWOFISH_SIZE> block1, std::span<const std::byte, TWOFISH_SIZE> block2)
{
    psafe3::Handle<gcry_cipher_hd_t, gcry_cipher_close> cipher;
    gcry_error_t err;
    err = gcry_cipher_open(&cipher.actual, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_ECB,
        GCRY_CIPHER_SECURE);
    if (err) {
        return std::unexpected(make_error_code(err));
    }

    assert(pass.size() == SHA256_SIZE);
    err = gcry_cipher_setkey(cipher(), pass.data(), SHA256_SIZE);
    if (err) {
        return std::unexpected(make_error_code(err));
    }

    SecureBytes random_key(2 * TWOFISH_SIZE);
    gcry_cipher_decrypt(cipher(), random_key.data(), TWOFISH_SIZE, block1.data(), TWOFISH_SIZE);
    gcry_cipher_reset(cipher());
    gcry_cipher_decrypt(cipher(), random_key.data(TWOFISH_SIZE), TWOFISH_SIZE, block2.data(),
        TWOFISH_SIZE);
    return std::move(random_key);
}

std::expected<Safe, std::error_code>
Safe::load(const std::filesystem::path& path,
    const std::vector<std::byte> pass_phrase)
{
    auto mapped_file = MappedFile::open(path.c_str());
    if (!mapped_file) {
        return std::unexpected(mapped_file.error());
    }
    auto& contents = mapped_file.value();
    // TODO Check if file size is < minimum viable safe size.
    if (MAGIC != contents.slice<MAGIC.size()>(PROLOGUE::MAGIC_OFFSET)) {
        return std::unexpected(psafe3::Error::invalid_magic);
    }

    // Validate the pass phrase against the hash in the prologue.
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
    if (key_hash != contents.slice<PROLOGUE::PASS_HASH_SIZE>(PROLOGUE::PASS_HASH_OFFSET)) {
        return std::unexpected(psafe3::Error::invalid_pass_phrase);
    }

    // Decrypt and verify database.
    gcry_error_t err;

    auto key_k_tmp = extract_random_key(key, contents.slice<PROLOGUE::B_SIZE>(PROLOGUE::OFFSET_B1),
        contents.slice<PROLOGUE::B_SIZE>(PROLOGUE::OFFSET_B2));
    if (!key_k_tmp) {
        return std::unexpected(key_k_tmp.error());
    }
    auto key_k = std::move(key_k_tmp.value());
    psafe3::Handle<gcry_cipher_hd_t, gcry_cipher_close> cipher;
    err = gcry_cipher_open(&cipher.actual, GCRY_CIPHER_TWOFISH,
        GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    if (err) {
        return std::unexpected(make_error_code(err));
    }
    err = gcry_cipher_setkey(cipher(), key_k.data(), SHA256_SIZE);
    if (err) {
        return std::unexpected(make_error_code(err));
    }
    err = gcry_cipher_setiv(cipher(), contents.slice(PROLOGUE::OFFSET_IV, PROLOGUE::IV_SIZE).data(), TWOFISH_SIZE);

    auto key_l_tmp = extract_random_key(key, contents.slice<PROLOGUE::B_SIZE>(PROLOGUE::OFFSET_B3),
        contents.slice<PROLOGUE::B_SIZE>(PROLOGUE::OFFSET_B4));
    if (!key_l_tmp) {
        return std::unexpected(key_l_tmp.error());
    }
    auto key_l = std::move(key_l_tmp.value());

    psafe3::Handle<gcry_md_hd_t, gcry_md_close> hmac;
    err = gcry_md_open(&hmac.actual, GCRY_MD_SHA256,
        GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
    if (err) {
        return std::unexpected(make_error_code(err));
    }
    err = gcry_md_setkey(hmac(), key_l.data(), SHA256_SIZE);
    if (err) {
        return std::unexpected(make_error_code(err));
    }

    auto encrypted = contents.slice(PROLOGUE_SIZE, contents.size() - (PROLOGUE_SIZE + TWOFISH_SIZE + SHA256_SIZE));
    assert(encrypted.size() > 0 && (encrypted.size() % TWOFISH_SIZE == 0));
    SecureBytes decrypted(encrypted.size());

    size_t offset = 0;
    while (offset < encrypted.size()) {
        err = gcry_cipher_decrypt(cipher(), decrypted.data(offset), TWOFISH_SIZE,
            encrypted.subspan(offset, TWOFISH_SIZE).data(), TWOFISH_SIZE);

        offset += TWOFISH_SIZE;
    }

    size_t epilogue_offset = PROLOGUE_SIZE + encrypted.size();
    if (contents.slice<TWOFISH_SIZE>(epilogue_offset) != DBEND) {
        return std::unexpected(psafe3::Error::corrupt_file);
    }

    // gcry_md_final(hmac());
    // std::array<std::byte, SHA256_SIZE> computed_hmac;
    // memmove(&computed_hmac[0], gcry_md_read(hmac(), GCRY_MD_SHA256), SHA256_SIZE);
    // if (computed_hmac != contents.slice<SHA256_SIZE>(epilogue_offset + TWOFISH_BYTES)) {
    //     return std::unexpected(psafe3::Error::hmac_mismatch);
    // }

    return Safe(contents.detach(), std::move(decrypted));
}
} // namespace psafe3
