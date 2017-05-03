#ifndef __LINE_GLIBC_RUNTIME_H_
#define __LINE_GLIBC_RUNTIME_H_

#include <stdint.h>

#include "rtld.h"
#include "logger.h"

class GlibcRuntime : Logger
{
 private:
    rtld_global_ro m_rtldGlobalRO;
    rtld_global m_rtldGlobal;

    int m_libc_enable_secure;

 public:
    GlibcRuntime();
    ~GlibcRuntime();

    uint64_t findSymbol(const char* symName);

    static uint64_t tls_get_addr();

    static void lock_recursive(void* lock);
    static void unlock_recursive(void* lock);

    static void* dl_find_dso_for_object(void* addr);

    static void* dl_open(
        const char *file,
        int mode,
        const void *caller_dlopen,
        Lmid_t nsid,
        int argc,
        char *argv[],
        char *env[]);
    static int dl_catch_error(
        const char **objname,
        const char **errstring,
        bool *mallocedp,
        void (*operate) (void *),
        void *args);

    static uint64_t dl_lookup_symbol_x(
        const char * symname,
        struct link_map * handle,
        const Elf64_Sym ** symbol,
        struct r_scope_elem *[],
        const struct r_found_version *,
        int, int,
        struct link_map *);

    static void dl_debug_printf(const char *, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
};

#endif
