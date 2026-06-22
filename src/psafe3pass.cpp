// https://github.com/marcbutler/libpsafe3/LICENSE

#include <iostream>
#include <locale.h>
#include <string.h>

#include <psafe3.h>
#include "util.h"

int main(int argc, char **argv)
{
    psafe3_err ret;

    setlocale(LC_ALL, "");

    if (argc != 3) {
        std::wcerr << L"Usage: " << widen(argv[0]) << L" <file> <password>\n";
        return 1;
    }

    ret = psafe3_setup();
    if (ret != PSAFE3_OK) {
        return 1;
    }

    ret = psafe3_verify_password(argv[1], (unsigned char *)argv[2], strlen(argv[2]));
    if (ret != PSAFE3_OK) {
        std::wcerr << L"Failed: " << widen(psafe3_strerror(ret)) << L'\n';
        return 1;
    }

    ret = psafe3_teardown();
    if (ret != PSAFE3_OK) {
        return 1;
    }

    return 0;
}
