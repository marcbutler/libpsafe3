// https://github.com/marcbutler/libpsafe3/LICENSE

#include <iomanip>
#include <iostream>
#include <vector>

#include "safe.h"
#include "safeio.h"
#include "utility.h"

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 3) {
        std::cerr << "Usage: psafe3dump <file> [<password>]\n";
        return 1;
    }

    std::string pass;
    if (argc == 3) {
        pass = argv[2];
    } else {
        char buf[100];
        size_t bufsz = sizeof(buf);
        if (read_from_terminal("Password: ", buf, &bufsz) != 0) {
            std::cerr << "No password read.\n";
            return 1;
        }
        pass = buf;
    }

    const auto* pass_bytes = reinterpret_cast<const std::byte*>(pass.data());
    std::vector<std::byte> pass_phrase(pass_bytes, pass_bytes + pass.size());

    auto result = psafe3::Safe::load(argv[1], std::move(pass_phrase));
    if (!result) {
        std::cerr << "Failed: " << result.error().message() << '\n';
        return 1;
    }
    auto& safe = result.value();

    auto print_field = [](uint8_t type, uint32_t len, auto&& print_value) {
        std::cout << "type=" << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<unsigned>(type) << std::dec << std::setfill(' ')
                  << "  len=" << std::right << std::setw(3) << len
                  << "  ";
        print_value();
        std::cout << '\n';
    };

    for (const auto& field : safe.header()) {
        print_field(static_cast<uint8_t>(field.type), field.len,
            [&] { psafe3::header_field_as_text(field, std::cout); });
    }

    for (const auto& record : safe.database()) {
        std::cout << '\n';
        for (const auto& field : record.fields) {
            print_field(static_cast<uint8_t>(field.type), field.len,
                [&] { psafe3::record_field_as_text(field, std::cout); });
        }
    }

    return 0;
}
