// https://github.com/marcbutler/libpsafe3/LICENSE

#include <array>
#include <expected>
#include <span>
#include <system_error>

#include "crypto.h"
#include "error.h"
#include "gcrypt.h"
#include "handle.h"
#include "mapped_file.h"
#include "safe.h"
#include "secure_bytes.h"
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
    auto key_hash_calc = psafe3::sha256(key.as_span());
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

    auto encrypted = contents.slice(PROLOGUE_SIZE, contents.size() - (PROLOGUE_SIZE + TWOFISH_SIZE + SHA256_SIZE));
    assert(encrypted.size() > 0 && (encrypted.size() % TWOFISH_SIZE == 0));
    SecureBytes decrypted(encrypted.size());

    size_t offset = 0;
    // Decrypted header fields.
    while (offset < encrypted.size()) {
        err = gcry_cipher_decrypt(cipher(), decrypted.data(offset), TWOFISH_SIZE,
            encrypted.subspan(offset, TWOFISH_SIZE).data(), TWOFISH_SIZE);
        offset += TWOFISH_SIZE;
    }

    size_t epilogue_offset = PROLOGUE_SIZE + encrypted.size();
    if (contents.slice<TWOFISH_SIZE>(epilogue_offset) != DBEND) {
        return std::unexpected(psafe3::Error::corrupt_file);
    }

    auto hmac_result = psafe3::SHA256HMA::create(key_l.as_span());
    if (!hmac_result)
        return std::unexpected(hmac_result.error());
    auto hmac = std::move(hmac_result.value());

    auto const LEN_SIZE = sizeof(std::uint32_t);
    std::vector<HeaderField> header;
    offset = 0;
    while (offset < decrypted.size()) {
        const auto field_type = static_cast<HeaderFieldType>(decrypted.byte(offset + LEN_SIZE));
        auto field_size = psafe3::load<std::endian::little>(decrypted.span<LEN_SIZE>(offset));
        auto data_size = field_size + LEN_SIZE + 1;
        auto block_size = align_up(data_size, TWOFISH_SIZE);
        if (field_type != HeaderFieldType::end_of_entry) {
            hmac.write(decrypted.span(offset + LEN_SIZE + 1, field_size));
            header.push_back(HeaderField {
                .type = field_type,
                .len = field_size,
                .data = decrypted.span(offset + LEN_SIZE + 1, field_size),
                .extent = decrypted.span(offset, block_size),
            });
        }
        offset += block_size;
        if (field_type == HeaderFieldType::end_of_entry)
            break;
    }
    std::vector<Record> database;
    while (offset < decrypted.size()) {
        if (decrypted.span<TWOFISH_SIZE>(offset) == DBEND) {
            offset += TWOFISH_SIZE;
            break;
        }
        Record record;
        size_t record_start = offset;
        while (offset < decrypted.size()) {
            const auto field_type = static_cast<RecordFieldType>(decrypted.byte(offset + LEN_SIZE));
            auto field_size = psafe3::load<std::endian::little>(decrypted.span<LEN_SIZE>(offset));
            auto data_size = field_size + LEN_SIZE + 1;
            auto block_size = align_up(data_size, TWOFISH_SIZE);
            if (field_type != RecordFieldType::end_of_entry) {
                hmac.write(decrypted.span(offset + LEN_SIZE + 1, field_size));
                record.fields.push_back(RecordField {
                    .type = field_type,
                    .len = field_size,
                    .data = decrypted.span(offset + LEN_SIZE + 1, field_size),
                    .extent = decrypted.span(offset, block_size),
                });
            }
            offset += block_size;
            if (field_type == RecordFieldType::end_of_entry)
                break;
        }
        record.data = decrypted.span(record_start, offset - record_start);
        record.extent = record.data;
        database.push_back(std::move(record));
    }

    auto computed_hmac = hmac.finish();
    if (!computed_hmac)
        return std::unexpected(computed_hmac.error());
    if (*computed_hmac != contents.slice<SHA256_SIZE>(epilogue_offset + TWOFISH_SIZE))
        return std::unexpected(psafe3::Error::hmac_mismatch);

    return Safe(contents.detach(), std::move(decrypted), std::move(header), std::move(database));
}

std::span<const HeaderField> Safe::header() const noexcept
{
    return header_;
}

std::span<const Record> Safe::database() const noexcept
{
    return database_;
}

} // namespace psafe3
