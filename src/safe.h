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
    version = 0x00,
    uuid = 0x01,
    non_default_preferences = 0x02,
    tree_display_status = 0x03,
    timestamp_of_last_save = 0x04,
    who_performed_last_save = 0x05,
    what_performed_last_save = 0x06,
    last_saved_by_user = 0x07,
    last_saved_on_host = 0x08,
    database_name = 0x09,
    database_description = 0x0a,
    database_filters = 0x0b,
    reserved_0c = 0x0c,
    reserved_0d = 0x0d,
    reserved_0e = 0x0e,
    recently_used_entries = 0x0f,
    named_password_policies = 0x10,
    empty_groups = 0x11,
    reserved_12 = 0x12,
    end_of_entry = 0xff,
};

enum class RecordFieldType : uint8_t {
    uuid = 0x01,
    group = 0x02,
    title = 0x03,
    username = 0x04,
    notes = 0x05,
    password = 0x06,
    creation_time = 0x07,
    password_modification_time = 0x08,
    last_access_time = 0x09,
    password_expiry_time = 0x0a,
    reserved_0b = 0x0b,
    last_modification_time = 0x0c,
    url = 0x0d,
    autotype = 0x0e,
    password_history = 0x0f,
    password_policy = 0x10,
    password_expiry_interval = 0x11,
    run_command = 0x12,
    double_click_action = 0x13,
    email_address = 0x14,
    protected_entry = 0x15,
    own_symbols_for_password = 0x16,
    shift_double_click_action = 0x17,
    password_policy_name = 0x18,
    entry_keyboard_shortcut = 0x19,
    end_of_entry = 0xff,
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
