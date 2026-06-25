// https://github.com/marcbutler/libpsafe3/LICENSE

#include <ctime>
#include <iomanip>
#include <ostream>
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

    void write_uuid(std::ostream& out, std::span<std::byte> data)
    {
        auto prev = out.flags();
        out << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10)
                out << '-';
            out << std::setw(2) << static_cast<unsigned>(data[i]);
        }
        out.flags(prev);
    }

    void write_time(std::ostream& out, std::span<std::byte> data)
    {
        std::time_t t = as_time(data);
        std::tm* tm = std::gmtime(&t);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
        out << buf;
    }

    void write_uint16(std::ostream& out, std::span<std::byte> data)
    {
        out << load<std::endian::little>(std::span<const std::byte, 2> { data.data(), 2 });
    }

    void write_uint32(std::ostream& out, std::span<std::byte> data)
    {
        out << load<std::endian::little>(std::span<const std::byte, 4> { data.data(), 4 });
    }

} // namespace

void header_field_as_text(const HeaderField& field, std::ostream& out)
{
    switch (field.type) {
    case HeaderFieldType::version:
        write_uint16(out, field.data);
        break;
    case HeaderFieldType::uuid:
        write_uuid(out, field.data);
        break;
    case HeaderFieldType::timestamp_of_last_save:
        write_time(out, field.data);
        break;
    case HeaderFieldType::non_default_preferences:
    case HeaderFieldType::tree_display_status:
    case HeaderFieldType::who_performed_last_save:
    case HeaderFieldType::what_performed_last_save:
    case HeaderFieldType::last_saved_by_user:
    case HeaderFieldType::last_saved_on_host:
    case HeaderFieldType::database_name:
    case HeaderFieldType::database_description:
    case HeaderFieldType::database_filters:
    case HeaderFieldType::recently_used_entries:
    case HeaderFieldType::named_password_policies:
    case HeaderFieldType::empty_groups:
    case HeaderFieldType::reserved_12:
        out << as_text(field.data);
        break;
    case HeaderFieldType::reserved_0c:
    case HeaderFieldType::reserved_0d:
    case HeaderFieldType::reserved_0e:
    case HeaderFieldType::end_of_entry:
        break;
    }
}

void record_field_as_text(const RecordField& field, std::ostream& out)
{
    switch (field.type) {
    case RecordFieldType::uuid:
        write_uuid(out, field.data);
        break;
    case RecordFieldType::creation_time:
    case RecordFieldType::password_modification_time:
    case RecordFieldType::last_access_time:
    case RecordFieldType::password_expiry_time:
    case RecordFieldType::last_modification_time:
        write_time(out, field.data);
        break;
    case RecordFieldType::password_expiry_interval:
    case RecordFieldType::double_click_action:
    case RecordFieldType::shift_double_click_action:
        write_uint16(out, field.data);
        break;
    case RecordFieldType::entry_keyboard_shortcut:
        write_uint32(out, field.data);
        break;
    case RecordFieldType::protected_entry:
        out << (field.data[0] != std::byte { 0 } ? "true" : "false");
        break;
    case RecordFieldType::group:
    case RecordFieldType::title:
    case RecordFieldType::username:
    case RecordFieldType::notes:
    case RecordFieldType::password:
    case RecordFieldType::url:
    case RecordFieldType::autotype:
    case RecordFieldType::password_history:
    case RecordFieldType::password_policy:
    case RecordFieldType::run_command:
    case RecordFieldType::email_address:
    case RecordFieldType::own_symbols_for_password:
    case RecordFieldType::password_policy_name:
        out << as_text(field.data);
        break;
    case RecordFieldType::reserved_0b:
    case RecordFieldType::end_of_entry:
        break;
    }
}

} // namespace psafe3
