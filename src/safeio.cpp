// https://github.com/marcbutler/libpsafe3/LICENSE

#include <ctime>
#include <format>
#include <span>
#include <string>

#include "safe.h"
#include "safeio.h"
#include "utility.h"

namespace psafe3 {

namespace {

    std::string as_text(std::span<std::byte> data)
    {
        return { reinterpret_cast<const char*>(data.data()), data.size() };
    }

    std::time_t as_time(std::span<std::byte> data)
    {
        return static_cast<std::time_t>(
            load<std::endian::little>(std::span<const std::byte, 4> { data.data(), 4 }));
    }

    std::string format_uuid(std::span<std::byte> data)
    {
        return std::format(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}"
            "-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            (unsigned)data[0],  (unsigned)data[1],  (unsigned)data[2],  (unsigned)data[3],
            (unsigned)data[4],  (unsigned)data[5],
            (unsigned)data[6],  (unsigned)data[7],
            (unsigned)data[8],  (unsigned)data[9],
            (unsigned)data[10], (unsigned)data[11], (unsigned)data[12],
            (unsigned)data[13], (unsigned)data[14], (unsigned)data[15]);
    }

    std::string format_time(std::span<std::byte> data)
    {
        std::time_t t = as_time(data);
        std::tm* tm = std::gmtime(&t);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
        return buf;
    }

    std::string format_uint16(std::span<std::byte> data)
    {
        return std::format("{}",
            load<std::endian::little>(std::span<const std::byte, 2> { data.data(), 2 }));
    }

    std::string format_uint32(std::span<std::byte> data)
    {
        return std::format("{}",
            load<std::endian::little>(std::span<const std::byte, 4> { data.data(), 4 }));
    }

} // namespace

std::string header_field_as_text(const HeaderField& field)
{
    switch (field.type) {
    case HeaderFieldType::VERSION:
        return format_uint16(field.data);
    case HeaderFieldType::UUID:
        return format_uuid(field.data);
    case HeaderFieldType::TIMESTAMP_OF_LAST_SAVE:
        return format_time(field.data);
    case HeaderFieldType::NON_DEFAULT_PREFERENCES:
    case HeaderFieldType::TREE_DISPLAY_STATUS:
    case HeaderFieldType::WHO_PERFORMED_LAST_SAVE:
    case HeaderFieldType::WHAT_PERFORMED_LAST_SAVE:
    case HeaderFieldType::LAST_SAVED_BY_USER:
    case HeaderFieldType::LAST_SAVED_ON_HOST:
    case HeaderFieldType::DATABASE_NAME:
    case HeaderFieldType::DATABASE_DESCRIPTION:
    case HeaderFieldType::DATABASE_FILTERS:
    case HeaderFieldType::RECENTLY_USED_ENTRIES:
    case HeaderFieldType::NAMED_PASSWORD_POLICIES:
    case HeaderFieldType::EMPTY_GROUPS:
    case HeaderFieldType::RESERVED_12:
        return as_text(field.data);
    case HeaderFieldType::RESERVED_0C:
    case HeaderFieldType::RESERVED_0D:
    case HeaderFieldType::RESERVED_0E:
    case HeaderFieldType::END_OF_ENTRY:
        return {};
    }
    return {};
}

std::string record_field_as_text(const RecordField& field)
{
    switch (field.type) {
    case RecordFieldType::UUID:
        return format_uuid(field.data);
    case RecordFieldType::CREATION_TIME:
    case RecordFieldType::PASSWORD_MODIFICATION_TIME:
    case RecordFieldType::LAST_ACCESS_TIME:
    case RecordFieldType::PASSWORD_EXPIRY_TIME:
    case RecordFieldType::LAST_MODIFICATION_TIME:
        return format_time(field.data);
    case RecordFieldType::PASSWORD_EXPIRY_INTERVAL:
    case RecordFieldType::DOUBLE_CLICK_ACTION:
    case RecordFieldType::SHIFT_DOUBLE_CLICK_ACTION:
        return format_uint16(field.data);
    case RecordFieldType::ENTRY_KEYBOARD_SHORTCUT:
        return format_uint32(field.data);
    case RecordFieldType::PROTECTED_ENTRY:
        return field.data[0] != std::byte { 0 } ? "true" : "false";
    case RecordFieldType::GROUP:
    case RecordFieldType::TITLE:
    case RecordFieldType::USERNAME:
    case RecordFieldType::NOTES:
    case RecordFieldType::PASSWORD:
    case RecordFieldType::URL:
    case RecordFieldType::AUTOTYPE:
    case RecordFieldType::PASSWORD_HISTORY:
    case RecordFieldType::PASSWORD_POLICY:
    case RecordFieldType::RUN_COMMAND:
    case RecordFieldType::EMAIL_ADDRESS:
    case RecordFieldType::OWN_SYMBOLS_FOR_PASSWORD:
    case RecordFieldType::PASSWORD_POLICY_NAME:
        return as_text(field.data);
    case RecordFieldType::RESERVED_0B:
    case RecordFieldType::END_OF_ENTRY:
        return {};
    }
    return {};
}

} // namespace psafe3
