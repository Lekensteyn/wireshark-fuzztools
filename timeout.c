/*
clang -shared -fPIC -o libtimeout.so timeout.c
*/

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sanitizer/common_interface_defs.h>

static void set_timeout(void) __attribute__((constructor));

static int timeout;

static void alarm_handler(int signum)
{
    fprintf(stderr, "\nERROR: timeout after %d seconds\n", timeout);
    __sanitizer_print_stack_trace();
    fprintf(stderr, "SUMMARY: timeout\n");
    _exit(1);
}

static void set_timeout(void)
{
    char *timeout_s = getenv("TIMEOUT");
    if (!timeout_s || (timeout = atoi(timeout_s)) <= 0) {
        return;
    }

    alarm(timeout);
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction(SIGALRM) failed");
        _exit(1);
    }

    /* Prevent hooking into the symbolizer and exploding. */
    unsetenv("LD_PRELOAD");
}
