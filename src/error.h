#pragma once
// LICENSE

#include <string>
#include <system_error>

#include <gpg-error.h>

namespace psafe3 {

struct GpgErrorCategory : std::error_category {
    const char* name() const noexcept override { return "gpg-error"; }
    std::string message(int ev) const override
    {
        return gpg_strerror(static_cast<gpg_error_t>(ev));
    }
};

inline const std::error_category& gpg_error_category()
{
    static GpgErrorCategory cat;
    return cat;
}

inline std::error_code make_error_code(gpg_error_t e)
{
    return { static_cast<int>(e), gpg_error_category() };
}

enum class Error : int {
    invalid_magic = 1,
    invalid_password,
    corrupt_file,
};

struct ErrorCategory : std::error_category {
    const char* name() const noexcept override
    {
        return "psafe3";
    }
    std::string message(int ev) const override
    {
        switch (static_cast<Error>(ev)) {
        case Error::invalid_magic:
            return "invalid file magic";
        case Error::invalid_password:
            return "invalid password";
        case Error::corrupt_file:
            return "corrupt file";
        default:
            return "unknown error";
        }
    }
};

inline const std::error_category& error_category()
{
    static psafe3::ErrorCategory cat;
    return cat;
}

inline std::error_code make_error_code(psafe3::Error e)
{
    return { static_cast<int>(e), psafe3::error_category() };
}

} // namespace psafe3

template <>
struct std::is_error_code_enum<psafe3::Error> : std::true_type {
};
