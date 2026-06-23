#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <expected>
#include <filesystem>
#include <system_error>
#include <vector>

#include "common.h"
#include "error.h"
#include "mapped_memory.h"

namespace psafe3 {

class Safe {
public:
    static std::expected<Safe, std::error_code>
    load(const std::filesystem::path& path,
        const std::vector<std::byte> pass_phrase);

private:
    MappedMemory ondisk_;

    Safe(MappedMemory&& ondisk)
        : ondisk_(std::move(ondisk))
    {
    }
};
} // namespace psafe3

struct safe {
    uintptr_t file_image;
    size_t file_size;
    char path[];
};

enum safe_prologue_off {
    SAFE_OFF_MAGIC = 0,
    SAFE_OFF_SALT = SAFE_OFF_MAGIC + PSAFE3_SIZE_MAGIC,
    SAFE_OFF_ITER = SAFE_OFF_SALT + PSAFE3_SIZE_SALT,
    SAFE_OFF_H_PPRIME = SAFE_OFF_ITER + PSAFE3_SIZE_ITER,
    SAFE_OFF_B1 = SAFE_OFF_H_PPRIME + PSAFE3_SIZE_PASS_HASH,
    SAFE_OFF_B2 = SAFE_OFF_B1 + PSAFE3_SIZE_B,
    SAFE_OFF_B3 = SAFE_OFF_B2 + PSAFE3_SIZE_B,
    SAFE_OFF_B4 = SAFE_OFF_B3 + PSAFE3_SIZE_B,
    SAFE_OFF_IV = SAFE_OFF_B4 + PSAFE3_SIZE_B,
    SAFE_PROLOGUE_SIZE = SAFE_OFF_IV + PSAFE3_SIZE_B
};

unsigned char const* safe_salt(struct safe*);
uint32_t safe_iter(struct safe*);
unsigned char const* safe_pass_hash(struct safe*);
unsigned char const* safe_b(struct safe*, unsigned);
unsigned char const* safe_iv(struct safe*);

psafe3_err safe_load_prologue(int fd, unsigned char* prologue);
