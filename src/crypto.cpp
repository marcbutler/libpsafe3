// https://github.com/marcbutler/libpsafe3/LICENSE

#include <memory>

#include "common.h"
#include "crypto.h"
#include "gcrypt.h"
#include "handle.h"
#include "util.h"

#define GCRY_FAILED(err) ((err) != GPG_ERR_NO_ERROR)

gcry_error_t crypto_init()
{
    if (!gcry_check_version(GCRYPT_VERSION)) {
        // TODO Provide diagnostic information.
        return -1;
    }

    gcry_error_t err;
    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    // Initialize secure memory pool to default size; currently 16KiB.
    err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    err = gcry_control(GCRYCTL_INIT_SECMEM, 65536, 0);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    // Allow on the fly expansion of the secure memory area. Minimum increment
    // is 32KiB.
    err = gcry_control(GCRYCTL_AUTO_EXPAND_SECMEM, 1);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    if (err != GPG_ERR_NO_ERROR) {
        return err;
    }

    return GPG_ERR_NO_ERROR;
}

gcry_error_t crypto_term()
{
    gcry_error_t err;
    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    if (GCRY_FAILED(err)) {
        return err;
    }

    // After secure memory support is terminated, assume all secure heap memory
    // is now invalid.
    err = gcry_control(GCRYCTL_TERM_SECMEM);
    if (GCRY_FAILED(err)) {
        return err;
    }

    err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    if (GCRY_FAILED(err)) {
        return err;
    }

    return GPG_ERR_NO_ERROR;
}

psafe3_err crypto_stretch_key(const unsigned char* pass, size_t passlen,
    const sha256_hash salt, long iterations,
    sha256_hash stretched_key)
{
    gcry_md_hd_t mdalgo;
    psafe3_err err;
    sha256_hash tmp;

    err = gcry_md_open(&mdalgo, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (CRYPTO_FAIL(err)) {
        return err;
    }

    gcry_md_write(mdalgo, pass, passlen);
    gcry_md_write(mdalgo, salt, sizeof(sha256_hash));
    memmove(tmp, gcry_md_read(mdalgo, 0), sizeof(tmp));

    assert(iterations > 0);
    while (iterations-- > 0) {
        gcry_md_reset(mdalgo);
        gcry_md_write(mdalgo, tmp, sizeof(tmp));
        memmove(tmp, gcry_md_read(mdalgo, 0), sizeof(tmp));
    }

    gcry_md_final(mdalgo);
    memmove(stretched_key, tmp, sizeof(sha256_hash));
    gcry_md_close(mdalgo);
    return GPG_ERR_NO_ERROR;
}

void* crypto_secure_malloc(size_t size)
{
    return gcry_malloc_secure(size);
}

void crypto_secure_free(void* ptr)
{
    gcry_free(ptr);
}

namespace psafe3 {

namespace {

    struct MdHandle {
        gcry_md_hd_t hd = nullptr;
        ~MdHandle()
        {
            if (hd) {
                gcry_md_close(hd);
            }
        }
    };

    std::error_code do_init()
    {
        if (!gcry_check_version(GCRYPT_VERSION)) {
            return make_error_code(GPG_ERR_GENERAL);
        }

        gcry_error_t err;
        err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
        if (err) {
            return make_error_code(err);
        }
        err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
        if (err) {
            return make_error_code(err);
        }
        err = gcry_control(GCRYCTL_AUTO_EXPAND_SECMEM, 1);
        if (err) {
            return make_error_code(err);
        }
        err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
        if (err) {
            return make_error_code(err);
        }

        struct CleanupOnTermination {
            ~CleanupOnTermination()
            {
                gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
                gcry_control(GCRYCTL_TERM_SECMEM);
                gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
            }
        };
        static CleanupOnTermination cleanup;

        return { };
    }

    std::error_code ensure_init()
    {
        static const std::error_code result = do_init();
        return result;
    }

} // namespace

std::expected<SecureBytes, std::error_code>
stretch_key(std::span<const std::byte> pass,
    std::span<const std::byte, SHA256_SIZE> salt, uint32_t iterations)
{
    if (auto err = ensure_init(); err) {
        return std::unexpected(err);
    }

    psafe3::Handle<gcry_md_hd_t, gcry_md_close> hd;
    gcry_error_t err = gcry_md_open(&hd.actual, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (err) {
        return std::unexpected(make_error_code(err));
    }

    gcry_md_write(hd(), pass.data(), pass.size());
    gcry_md_write(hd(), salt.data(), salt.size());

    SecureBytes tmp(SHA256_SIZE);
    std::memcpy(tmp.data(), gcry_md_read(hd(), 0), SHA256_SIZE);

    for (uint32_t i = 0; i < iterations; ++i) {
        gcry_md_reset(hd());
        gcry_md_write(hd(), tmp.data(), SHA256_SIZE);
        std::memcpy(tmp.data(), gcry_md_read(hd(), 0), SHA256_SIZE);
    }

    return tmp;
}

std::expected<std::array<std::byte, SHA256_SIZE>, std::error_code>
sha256(std::span<const std::byte> data)
{
    if (auto err = ensure_init(); err) {
        return std::unexpected(err);
    }

    psafe3::Handle<gcry_md_hd_t, gcry_md_close> hd;
    gcry_error_t err = gcry_md_open(&hd.actual, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (err) {
        return std::unexpected(make_error_code(err));
    }

    gcry_md_write(hd(), data.data(), data.size());
    err = gcry_md_final(hd());
    if (err) {
        return std::unexpected(make_error_code(err));
    }

    const auto* hash = gcry_md_read(hd(), 0);
    if (!hash) {
        return std::unexpected(make_error_code(GPG_ERR_GENERAL));
    }

    std::array<std::byte, SHA256_SIZE> result;
    std::memcpy(result.data(), hash, SHA256_SIZE);
    return result;
}

SHA256HMA::~SHA256HMA()
{
    if (hd_)
        gcry_md_close(hd_);
}

SHA256HMA::SHA256HMA(SHA256HMA&& o) noexcept
    : hd_(o.hd_)
{
    o.hd_ = nullptr;
}

SHA256HMA& SHA256HMA::operator=(SHA256HMA&& o) noexcept
{
    if (this != &o) {
        if (hd_)
            gcry_md_close(hd_);
        hd_ = o.hd_;
        o.hd_ = nullptr;
    }
    return *this;
}

std::expected<SHA256HMA, std::error_code> SHA256HMA::create(std::span<const std::byte> key)
{
    if (auto err = ensure_init(); err)
        return std::unexpected(err);

    gcry_md_hd_t hd;
    gcry_error_t err = gcry_md_open(&hd, GCRY_MD_SHA256,
        GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
    if (err)
        return std::unexpected(make_error_code(err));

    err = gcry_md_setkey(hd, key.data(), key.size());
    if (err) {
        gcry_md_close(hd);
        return std::unexpected(make_error_code(err));
    }
    return SHA256HMA(hd);
}

void SHA256HMA::write(std::span<const std::byte> data)
{
    gcry_md_write(hd_, data.data(), data.size());
}

std::expected<std::array<std::byte, SHA256_SIZE>, std::error_code> SHA256HMA::finish()
{
    gcry_md_final(hd_);
    const auto* hash = gcry_md_read(hd_, GCRY_MD_SHA256);
    if (!hash)
        return std::unexpected(make_error_code(GPG_ERR_GENERAL));
    std::array<std::byte, SHA256_SIZE> result;
    std::memcpy(result.data(), hash, SHA256_SIZE);
    return result;
}

} // namespace psafe3

psafe3_err crypto_sha256md(const unsigned char* in, unsigned char* out,
    size_t len)
{
    gcry_md_hd_t hd;
    gcry_error_t err;
    const unsigned char* hash;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (err != GPG_ERR_NO_ERROR) {
        goto exit_with_error;
    }
    gcry_md_write(hd, in, len);
    err = gcry_md_final(hd);
    if (err != GPG_ERR_NO_ERROR) {
        goto close_with_err;
    }

    hash = gcry_md_read(hd, 0);
    if (hash == NULL) {
        goto close_with_err;
    }
    memmove(out, hash, sizeof(sha256_hash));

close_with_err:
    gcry_md_close(hd);
exit_with_error:
    return err;
}
