// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cstring>
#include <iostream>
#include <vector>

#include "safe.h"

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <file> <password>\n";
        return 1;
    }

    const auto* pass = reinterpret_cast<const std::byte*>(argv[2]);
    std::vector<std::byte> pass_phrase(pass, pass + std::strlen(argv[2]));

    auto safe_path = std::filesystem::path(argv[1]);
    auto result = psafe3::Safe::load(safe_path, std::move(pass_phrase));
    if (!result) {
        std::cerr << "Failed: " << result.error().message() << '\n';
        return 1;
    }

    return 0;
}
