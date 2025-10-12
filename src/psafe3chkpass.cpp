/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include <psafe3.h>

int main(int argc, char **argv)
{
    psafe3_err ret;

    setlocale(LC_ALL, "");

    if (argc != 3) {
        fwprintf(stderr, L"Usage: %s <file> <password>\n", argv[0]);
        return 1;
    }

    ret = psafe3_setup();
    if (ret != PSAFE3_SUCCESS) {
        return 1;
    }

    ret = psafe3_verify_password(argv[1], (unsigned char *)argv[2], (long)strlen(argv[2]));
    if (ret != PSAFE3_SUCCESS) {
        fwprintf(stderr, L"Failed: %s\n", psafe3_strerror(ret));
        return 1;
    }

    ret = psafe3_teardown();
    if (ret != PSAFE3_SUCCESS) {
        return 1;
    }

    return 0;
}
