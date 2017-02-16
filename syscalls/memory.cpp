/*
 * This contains the syscalls related to memory handling
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "kernel.h"
#include "process.h"
#include "memory.h"

SYSCALL_METHOD(mmap)
{
    uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
    uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
    uint64_t prot = ucontext->uc_mcontext->__ss.__rdx;
    uint64_t flags = ucontext->uc_mcontext->__ss.__r10;
    uint64_t fd = ucontext->uc_mcontext->__ss.__r8;
    uint64_t off = ucontext->uc_mcontext->__ss.__r9;

    int darwinFlags = 0;

    if (flags & LINUX_MAP_SHARED)
    {
        darwinFlags |= MAP_SHARED;
    }
    if (flags & LINUX_MAP_PRIVATE)
    {
        darwinFlags |= MAP_PRIVATE;
    }
    if (flags & LINUX_MAP_FIXED)
    {
        darwinFlags |= MAP_FIXED;
    }
    if (flags & LINUX_MAP_ANONYMOUS)
    {
        darwinFlags |= MAP_ANON;
        fd = 0;
    }
    if (flags & LINUX_MAP_NORESERVE)
    {
        darwinFlags |= MAP_NORESERVE;
    }
    prot &= 0x7;
#ifdef DEBUG
    log(
        "execSyscall: sys_mmap: addr=0x%llx, len=%llu, prot=0x%llx, flags=0x%llx->%x, fd=%lld, off=%lld",
        addr,
        len,
        prot,
        flags,
        darwinFlags,
        fd,
        off);
#endif
    void* result = mmap((void*)addr, len, prot, darwinFlags, fd, off);
    int err = errno;
#ifdef DEBUG
    log("execSyscall: sys_mmap: -> result=%p, errno=%d", result, err);
#endif
    syscallErrnoResult(ucontext, (uint64_t)result, result != NULL, err);
    return true;
}

SYSCALL_METHOD(mprotect)
{
    uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
    uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
    uint64_t prot = ucontext->uc_mcontext->__ss.__rdx & 7; // Only the RWX flags
#ifdef DEBUG
    log("execSyscall: sys_mprotext: addr=0x%llx, len=%llu, prot=0x%llx", addr, len, prot);
#endif

    int res = mprotect((void*)addr, len, prot);
    int err = errno;
#ifdef DEBUG
    log("execSyscall: sys_mprotext:  -> res=%d", res);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);
    return true;
}

SYSCALL_METHOD(munmap)
{
    uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
    uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
    log("execSyscall: sys_munmap: addr=0x%llx, len=%llu", addr, len);
#endif

    int res = munmap((void*)addr, len);
    int err = errno;

#ifdef DEBUG
    log("execSyscall: sys_munmap: -> res=%d", res);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);
    return true;
}

SYSCALL_METHOD(brk)
{
    uint64_t brkarg = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
    log("execSyscall: sys_brk: brkarg=0x%llx", brkarg);
#endif

    uint64_t currentBrk = m_process->getBrk();

    if (brkarg == 0)
    {
        ucontext->uc_mcontext->__ss.__rax = currentBrk;
    }
    else
    {
        uint64_t newbrk = ALIGN(brkarg, 4096);
        uint64_t len = newbrk - currentBrk;
#ifdef DEBUG
        log("execSyscall: sys_brk: newbrk=0x%llx, len=%llx", newbrk, len);
#endif
        void* maddr = mmap((void*)currentBrk, len,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_FIXED | MAP_ANON | MAP_PRIVATE,
            -1,
            0);
        int err = errno;
#ifdef DEBUG
        log("execSyscall: sys_brk:  -> maddr=%p, errno=%d", maddr, err);
#endif
        if (maddr != NULL)
        {
            m_process->setBrk(newbrk);
        }
        syscallErrnoResult(ucontext, newbrk, maddr != NULL, err);
    }
#ifdef DEBUG
    log("execSyscall: sys_brk: returning: 0x%llx", ucontext->uc_mcontext->__ss.__rax);
#endif
    return true;
}

SYSCALL_METHOD(msync)
{
    void* addr = (void*)(ucontext->uc_mcontext->__ss.__rdi);
    size_t len = ucontext->uc_mcontext->__ss.__rsi;
    int flags = ucontext->uc_mcontext->__ss.__rdx;

#ifdef DEBUG
    log("sys_msync: addr=%p, len=%ld, flags=%d", addr, len, flags);
#endif
    int res = msync(addr, len, flags);
    int err = errno;
#ifdef DEBUG
    log("sys_msync: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);
    return true;
}

SYSCALL_METHOD(mincore)
{
    unsigned long start = ucontext->uc_mcontext->__ss.__rdi;
    size_t len = ucontext->uc_mcontext->__ss.__rsi;
    char* vec = (char*)(ucontext->uc_mcontext->__ss.__rdx);
#ifdef DEBUG
    log("sys_mincore: start=0x%lx, len=%ld, vec=%p", start, len, vec);
#endif
    int res;
    res = mincore((void*)start, len, vec);
    int err = errno;
#ifdef DEBUG
    log("sys_mincore: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res != -1, err);
    return true;
}

SYSCALL_METHOD(mlock)
{
    void* addr = (void*)(ucontext->uc_mcontext->__ss.__rdi);
    unsigned long len = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
    log("sys_mlock: addr=%p, len=%ld", addr, len);
#endif
    int res;
    res = mlock(addr, len);
    int err = errno;
#ifdef DEBUG
    log("sys_mlock: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}


