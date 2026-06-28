#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <expected>
#include <filesystem>
#include <span>
#include <system_error>
#include <vector>

#include <cstdint>

#include "crypto.h"
#include "mapped.h"

namespace psafe3 {

enum class HeaderFieldType : uint8_t {
    VERSION = 0x00,
    UUID = 0x01,
    NON_DEFAULT_PREFERENCES = 0x02,
    TREE_DISPLAY_STATUS = 0x03,
    TIMESTAMP_OF_LAST_SAVE = 0x04,
    WHO_PERFORMED_LAST_SAVE = 0x05,
    WHAT_PERFORMED_LAST_SAVE = 0x06,
    LAST_SAVED_BY_USER = 0x07,
    LAST_SAVED_ON_HOST = 0x08,
    DATABASE_NAME = 0x09,
    DATABASE_DESCRIPTION = 0x0a,
    DATABASE_FILTERS = 0x0b,
    RESERVED_0C = 0x0c,
    RESERVED_0D = 0x0d,
    RESERVED_0E = 0x0e,
    RECENTLY_USED_ENTRIES = 0x0f,
    NAMED_PASSWORD_POLICIES = 0x10,
    EMPTY_GROUPS = 0x11,
    RESERVED_12 = 0x12,
    END_OF_ENTRY = 0xff,
};

enum class RecordFieldType : uint8_t {
    UUID = 0x01,
    GROUP = 0x02,
    TITLE = 0x03,
    USERNAME = 0x04,
    NOTES = 0x05,
    PASSWORD = 0x06,
    CREATION_TIME = 0x07,
    PASSWORD_MODIFICATION_TIME = 0x08,
    LAST_ACCESS_TIME = 0x09,
    PASSWORD_EXPIRY_TIME = 0x0a,
    RESERVED_0B = 0x0b,
    LAST_MODIFICATION_TIME = 0x0c,
    URL = 0x0d,
    AUTOTYPE = 0x0e,
    PASSWORD_HISTORY = 0x0f,
    PASSWORD_POLICY = 0x10,
    PASSWORD_EXPIRY_INTERVAL = 0x11,
    RUN_COMMAND = 0x12,
    DOUBLE_CLICK_ACTION = 0x13,
    EMAIL_ADDRESS = 0x14,
    PROTECTED_ENTRY = 0x15,
    OWN_SYMBOLS_FOR_PASSWORD = 0x16,
    SHIFT_DOUBLE_CLICK_ACTION = 0x17,
    PASSWORD_POLICY_NAME = 0x18,
    ENTRY_KEYBOARD_SHORTCUT = 0x19,
    END_OF_ENTRY = 0xff,
};

template <typename E>
struct Field {
    friend class Safe;

    E type;
    uint32_t len;
    std::span<std::byte> data;
    std::span<std::byte> extent;
};

using HeaderField = Field<HeaderFieldType>;
using RecordField = Field<RecordFieldType>;

struct Record {
    friend class Safe;

    std::span<std::byte> data;
    std::vector<RecordField> fields;
    std::span<std::byte> extent;
};

class Safe {
public:
    static std::expected<Safe, std::error_code>
    load(const std::filesystem::path& path,
        const std::vector<std::byte> pass_phrase);

    std::span<const HeaderField> header() const noexcept;
    std::span<const Record> database() const noexcept;

private:
    MappedMemory ondisk_;
    SecureBytes decrypted_;
    std::vector<HeaderField> header_;
    std::vector<Record> database_;

    Safe(MappedMemory&& ondisk, SecureBytes&& decrypted,
        std::vector<HeaderField>&& header, std::vector<Record>&& database)
        : ondisk_(std::move(ondisk))
        , decrypted_(std::move(decrypted))
        , header_(std::move(header))
        , database_(std::move(database))
    {
    }
};
} // namespace psafe3
