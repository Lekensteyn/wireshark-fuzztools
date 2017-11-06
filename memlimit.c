/*
clang -shared -fPIC -o libmemlimit.so memlimit.c
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sanitizer/common_interface_defs.h>

static void set_memlimit(void) __attribute__((constructor));

static size_t maxSize;

void __sanitizer_malloc_hook(const volatile void *ptr, size_t size)
{
    if (maxSize && size > maxSize) {
        fprintf(stderr, "\nAllocation too large: %zu > %zu (%#zx > %#zx)\n",
                size, maxSize, size, maxSize);
        __sanitizer_print_stack_trace();
        fprintf(stderr, "SUMMARY: large memory allocation request: %zu\n", size);
        _exit(1);
    }
}

static void set_memlimit(void)
{
    char *memlimit_s = getenv("MEMLIMIT");
    if (memlimit_s) {
        maxSize = strtoull(memlimit_s, NULL, 0);
    }

    /* Prevent hooking into the symbolizer and exploding. */
    unsetenv("LD_PRELOAD");
}
