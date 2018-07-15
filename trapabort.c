/*
clang -shared -fPIC -o libtrapabort.so trapabort.c
*/

#include <stdlib.h>
#include <signal.h>

static void set_sigtrap_handler(void) __attribute__((constructor));

static void abort_handler(int sig)
{
    abort();
}

static void set_sigtrap_handler(void)
{
    struct sigaction sigact = {
        .sa_handler = abort_handler,
    };
    sigaction(SIGTRAP, &sigact, NULL);
}
