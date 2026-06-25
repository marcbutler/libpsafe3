// https://github.com/marcbutler/libpsafe3/LICENSE

#include "crypto.h"
#include "gcrypt.h"
#include "handle.h"

namespace psafe3 {

namespace {

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
        err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
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
