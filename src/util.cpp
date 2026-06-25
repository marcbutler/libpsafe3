// https://github.com/marcbutler/libpsafe3/LICENSE

#include <cassert>
#include <cstdio>
#include <cstring>
#include <termios.h>
#include <unistd.h>

#include "utility.h"

int read_from_terminal(const char* prompt, char* buf, size_t* bufsize)
{
    assert(prompt && buf && bufsize);
    struct termios t;

    puts(prompt);
    fflush(stdout);

    tcgetattr(STDIN_FILENO, &t);
    t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);

    memset(buf, 0, *bufsize);
    if (fgets(buf, *bufsize, stdin) == NULL) {
        return -1;
    }
    size_t len = strlen(buf);
    buf[len - 1] = 0;

    tcgetattr(STDIN_FILENO, &t);
    t.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);

    return 0;
}
