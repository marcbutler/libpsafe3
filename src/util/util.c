#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <wchar.h>

#include "util.h"

void crash_actual(const char *path, const char *func)
{
    // FIXME See if arguments should be wide char.
    fwprintf(stderr, L"CRASH %s:%s\n", path, func);
#ifdef NDEBUG
    abort();
#else

#if __clang__
    // Prefer clang.
    __builtin_debugtrap();
#elif __GNUC__
    __builtin_trap();
#else
    abort();
#endif
#endif

}

void util_close_fd(int fd)
{
    int ret;

call_again:
    ret = close(fd);
    if (ret != 0) {
        switch (errno) {
        case EINTR:
            goto call_again;
        default:
            crash();
        }
    }
}

int read_from_terminal(const char *prompt, char *buf, size_t *bufsize)
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
