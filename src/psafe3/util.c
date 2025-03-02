/* https://github.com/marcbutler/libpsafe3/LICENSE */

#include <errno.h>
#include <stdio.h>
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
/* Prefer clang. */
#    if __clang__
    __builtin_debugtrap();
#    elif __GNUC__
    __builtin_trap();
#    else
    abort();
#    endif
#endif
}

/*
 * Wide character version of perror().
 */
void wperror(wchar_t *msg)
{
    if (msg == NULL || *msg == 0) {
        fwprintf(stderr, L"%s", strerror(errno));
    } else {
        fwprintf(stderr, L"%s: %s", msg, strerror(errno));
    }
}

/*
 * Close file descriptor. On error output message to stderr.
 */
void checked_close(int fd)
{
    int ret;

    assert_fd(fd);
    ret = close(fd);
    if (ret != 0) {
        /*
         * Though POSIX allows the descriptor to still be valid for some errors,
         * do not attempt to call close() again even for EINTR.
         * See the Linux close(2) man page as to why.
         */
        wperror(L"close()");
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
