
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "glibcruntime.h"
#include "process.h"
#include "elflibrary.h"

GlibcRuntime::GlibcRuntime() : Logger("GlibcRuntime")
{
    memset(&m_rtldGlobalRO, 0, sizeof(m_rtldGlobalRO));
    m_rtldGlobalRO._dl_debug_mask = 0;
    m_rtldGlobalRO._dl_pagesize = 4096;
    m_rtldGlobalRO._dl_catch_error = GlibcRuntime::dl_catch_error;
    m_rtldGlobalRO._dl_lookup_symbol_x = GlibcRuntime::dl_lookup_symbol_x;
    m_rtldGlobalRO._dl_open = GlibcRuntime::dl_open;
    m_rtldGlobalRO._dl_debug_printf = GlibcRuntime::dl_debug_printf;


    memset(&m_rtldGlobal, 0, sizeof(m_rtldGlobal));
    m_rtldGlobal._dl_nns = 1;
    m_rtldGlobal._dl_error_catch_tsd = (void**(*)())0xbeefface;
    m_rtldGlobal._dl_rtld_lock_recursive = GlibcRuntime::lock_recursive;
    m_rtldGlobal._dl_rtld_unlock_recursive = GlibcRuntime::unlock_recursive;

    m_libc_enable_secure = 0;
}

GlibcRuntime::~GlibcRuntime()
{
}

uint64_t GlibcRuntime::findSymbol(const char* symName)
{
    uint64_t value = 0;
    if (!strcmp(symName, "_rtld_global"))
    {
        value = (uint64_t)(&m_rtldGlobal);
    }
    else if (!strcmp(symName, "_rtld_global_ro"))
    {
        value = (uint64_t)(&m_rtldGlobalRO);
    }
    else if (!strcmp(symName, "__tls_get_addr"))
    {
        value = (uint64_t)(GlibcRuntime::tls_get_addr);
    }
    else if (!strcmp(symName, "_dl_find_dso_for_object"))
    {
        value = (uint64_t)(GlibcRuntime::dl_find_dso_for_object);
    }
    else if (!strcmp(symName, "__libc_enable_secure"))
    {
        value = (uint64_t)(&m_libc_enable_secure);
    }

    return value;
}

uint64_t GlibcRuntime::tls_get_addr()
{
    return LineProcess::getProcess()->getFSPtr();
}

void GlibcRuntime::lock_recursive(void* lock)
{
    // TODO: Implement
}

void GlibcRuntime::unlock_recursive(void* lock)
{
    // TODO: Implement
}

void* GlibcRuntime::dl_find_dso_for_object(void* addr)
{
    // TODO: Implement
    return NULL;
}

void* GlibcRuntime::dl_open(
    const char *file,
    int mode,
    const void *caller_dlopen,
    Lmid_t nsid,
    int argc,
    char *argv[],
    char *env[])
{
#ifdef DEBUG
    log("dl_open: file=%s, argc=%d, argv=%p, env=%p\n", file, argc, argv, env);
#endif
    ElfLibrary* lib = LineProcess::getProcess()->getExec()->loadLibrary(file, true, argc, argv, env);
    if (lib == NULL)
    {
        return NULL;
    }

    link_map* map = new link_map();
    map->l_addr = (Elf64_Addr)lib;

    return map;
}

int GlibcRuntime::dl_catch_error(
    const char **objname,
    const char **errstring,
    bool *mallocedp,
    void (*operate) (void *),
    void *args)
{
#ifdef DEBUG
    log("dl_catch_error: objname=%p, errstring=%p", objname, errstring);
#endif
    (*operate)(args);
    return 0;
}

uint64_t GlibcRuntime::dl_lookup_symbol_x(
    const char * symname,
    struct link_map * handle,
    const Elf64_Sym ** symbol,
    struct r_scope_elem *[],
    const struct r_found_version *,
    int, int,
    struct link_map *)
{
#ifdef DEBUG
    log("dl_lookup_symbol_x: symname=%s, handle=%p", symname, handle);
#endif
    link_map* map = (link_map*)handle;
    ElfLibrary* library = (ElfLibrary*)(map->l_addr);
#ifdef DEBUG
    log("dl_lookup_symbol_x: library=%s", library->getPath());
#endif
    *symbol = library->findSymbol(symname);
#ifdef DEBUG
    log("dl_lookup_symbol_x: symbol=%p", symbol);
#endif
    if (*symbol == NULL)
    {
        return 0;
    }

    link_map* symmap = new link_map();
    symmap->l_addr = library->getBase();
    symmap->l_name = (char*)symname;
    return (uint64_t)symmap;
}

void GlibcRuntime::dl_debug_printf(const char* format, ...)
{
    va_list va;
    va_start(va, format);

    char buf[4096];
    vsnprintf(buf, 4096, format, va);

    char timeStr[256];
    time_t t;
    struct tm *tm;
    t = time(NULL);
    tm = localtime(&t);
    strftime(timeStr, 256, "%Y/%m/%d %H:%M:%S", tm);

    pid_t pid = getpid();

    printf("%s: %d: dl_debug_printf: %s", timeStr, pid, buf);

    va_end(va);
}

