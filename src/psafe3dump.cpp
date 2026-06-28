// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cstring>
#include <cstring>
#include <format>
#include <iostream>
#include <print>
#include <vector>

#include "safe.h"
#include "safeio.h"

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "Usage: psafe3dump <file> <password>\n";
        return 1;
    }

    const auto* pass_bytes = reinterpret_cast<const std::byte*>(argv[2]);
    std::vector<std::byte> pass_phrase(pass_bytes, pass_bytes + std::strlen(argv[2]));

    auto result = psafe3::Safe::load(argv[1], std::move(pass_phrase));
    if (!result) {
        std::cerr << "Failed: " << result.error().message() << '\n';
        return 1;
    }
    auto& safe = result.value();

    auto print_field = [](uint8_t type, uint32_t len, std::string value) {
        std::println(std::cout, "type={:02x}  len={:3}  {}", type, len, value);
    };

    for (const auto& field : safe.header()) {
        print_field(static_cast<uint8_t>(field.type), field.len,
            psafe3::header_field_as_text(field));
    }

    for (const auto& record : safe.database()) {
        std::println(std::cout, "");
        for (const auto& field : record.fields) {
            print_field(static_cast<uint8_t>(field.type), field.len,
                psafe3::record_field_as_text(field));
        }
    }

    return 0;
}
