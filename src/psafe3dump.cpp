// https://github.com/marcbutler/libpsafe3/LICENSE

#include <assert.h>
#include <iomanip>
#include <iostream>
#include <locale.h>

#include "mapped_file.h"
#include "psafe.h"
#include "pws3.h"

#include "psafe3.h"
#include "util.h"

static void gcrypt_fatal(gcry_error_t err)
{
    std::wcerr << L"gcrypt error " << widen(gcry_strsource(err))
               << L"/" << widen(gcry_strerror(err)) << L'\n';
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    int ret;
    char pass[100];
    setlocale(LC_ALL, "");

    if (argc != 2 && argc != 3) {
        std::wcout << L"Usage: psafe file.psafe3\n";
        exit(EXIT_FAILURE);
    }

    if (argc == 3) {
        strcpy(pass, argv[2]);
    } else {
        size_t passmax = sizeof(pass);
        if (read_from_terminal("Password: ", pass, &passmax) != 0) {
            std::wcout << L"No password read.";
            exit(EXIT_FAILURE);
        }
    }

    if (psafe3_setup() != 0) {
        std::wcout << L"Failed to initialize psafe3 library.";
        exit(EXIT_FAILURE);
    }

    auto mapping = MappedFile::open(argv[1]);
    if (!mapping) {
        std::wcerr << L"Failed to open file: "
                   << widen(mapping.error().message().c_str()) << L'\n';
        exit(EXIT_FAILURE);
    }
    const unsigned char* ptr = (const unsigned char*)mapping->base();
    size_t sz = mapping->size();

    struct pws3_header hdr;
    if (psafe3_parse_header((void*)ptr, sz, &hdr) != 0) {
        std::wcerr << L"Error reading psafe3 header.";
        exit(EXIT_FAILURE);
    }

    struct safe_sec* sec;
    sec = (struct safe_sec*)gcry_malloc_secure(sizeof(*sec));
    if (sec == NULL) {
        std::wcout << L"Failed to allocate secure memory.\n";
        exit(EXIT_FAILURE);
    }

    ret = stretch_and_check_pass(pass, strlen(pass), &hdr, sec);
    if (ret != 0) {
        gcry_free(sec);
        std::wcout << L"Invalid password.\n";
        exit(1);
    }

    uint8_t* safe;
    size_t safe_size;
    safe_size = sz - (4 + sizeof(hdr) + 48);
    assert(safe_size > 0);
    assert(safe_size % TWOFISH_SIZE == 0);
    safe = (uint8_t*)gcry_malloc_secure(safe_size);
    if (safe == NULL) {
        std::wcout << L"Failed to allocate secure memory.\n";
        exit(EXIT_FAILURE);
    }

    gcry_error_t gerr;
    struct crypto_ctx ctx;
    if (init_decrypt_ctx(&ctx, &hdr, sec) < 0) {
        gcrypt_fatal(ctx.gerr);
    }

    size_t bcnt;
    bcnt = safe_size / TWOFISH_SIZE;
    assert(bcnt > 0);
    const uint8_t* encp;
    uint8_t* safep;
    encp = ptr + 4 + sizeof(hdr);
    safep = safe;
    uint8_t* safe_end = safep + safe_size;
    while (bcnt && (safep < safe_end)) {
        gerr = gcry_cipher_decrypt(ctx.cipher, safep, TWOFISH_SIZE, encp,
            TWOFISH_SIZE);
        if (gerr != GPG_ERR_NO_ERROR) {
            gcrypt_fatal(gerr);
        }
        safep += TWOFISH_SIZE;
        encp += TWOFISH_SIZE;
        bcnt--;
    }
    assert(bcnt == 0);

    enum { HDR,
        DB };
    int state = HDR;
    safep = safe;
    while (safep < safe + safe_size) {
        struct field* fld;
        fld = (struct field*)safep;
        {
            auto flags = std::wcout.flags();
            auto fill = std::wcout.fill(L'0');
            std::wcout << L"type=" << std::hex << std::setw(2)
                       << static_cast<unsigned>(fld->type);
            std::wcout.flags(flags);
            std::wcout.fill(fill);
        }
        std::wcout << L"  len=" << std::left << std::setw(3) << fld->len
                   << std::right << L"  ";
        if (state == DB) {
            dump_db_field(std::wcout, fld);
        } else {
            dump_hdr_field(std::wcout, fld);
        }
        if (fld->type == 0xff) {
            state = DB;
        }
        std::wcout << L'\n';
        if (fld->len) {
            gcry_md_write(ctx.hmac, safep + sizeof(*fld), fld->len);
        }
        safep += ((fld->len + 5 + 15) / TWOFISH_SIZE) * TWOFISH_SIZE;
    }

    assert(memcmp(ptr + (sz - 48), "PWS3-EOFPWS3-EOF", TWOFISH_SIZE) == 0);

    std::wcout << L'\n';
    dump_prologue(std::wcout, &hdr);
    std::wcout << L"KEY    ";
    dump_bytes(std::wcout, sec->pprime, SHA256_SIZE);
    std::wcout << L'\n';
    std::wcout << L"H(KEY) ";
    dump_bytes(std::wcout, hdr.h_pprime, SHA256_SIZE);
    std::wcout << L'\n';

    gcry_md_final(ctx.hmac);
    std::wcout << L"HMAC'  ";
    uint8_t hmac[32];
    memmove(hmac, gcry_md_read(ctx.hmac, GCRY_MD_SHA256), SHA256_SIZE);
    dump_bytes(std::wcout, hmac, SHA256_SIZE);
    std::wcout << L'\n';

    std::wcout << L"HMAC   ";
    dump_bytes(std::wcout, ptr + (sz - SHA256_SIZE), SHA256_SIZE);
    std::wcout << L'\n';

    gcry_free(safe);
    gcry_free(sec);

    term_decrypt_ctx(&ctx);
    if (psafe3_teardown() != 0) {
        std::wcout << L"Error terminating psafe3 library.";
        exit(EXIT_FAILURE);
    }

    exit(0);
}
