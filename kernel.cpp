
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "kernel.h"
#include "process.h"

syscall_t LinuxKernel::m_syscalls[] =
{
#include "syscalltable.h"
};

LinuxKernel::LinuxKernel(LineProcess* process)
{
    m_process = process;
}

LinuxKernel::~LinuxKernel()
{
}

bool LinuxKernel::syscall(uint64_t syscall, ucontext_t* ucontext)
{
    if (syscall >= (sizeof(m_syscalls) / sizeof(syscall_t)))
    {
        printf("LinuxKernel::syscall: Invalid syscall: %lld\n", syscall);
        m_process->printregs(ucontext);
        exit(255);
    }
    bool res = (this->*m_syscalls[syscall])(syscall, ucontext);
    if (!res)
    {
        printf("LinuxKernel::syscall: syscall failed: %lld\n", syscall);
        m_process->printregs(ucontext);
        exit(255);
    }
    return true;
}

SYSCALL_METHOD(notimplemented)
{
    log("Unimplemented syscall: %llu", syscall);
    return false;
}

static int errno2linux(int err)
{
    int linux_errno = err;

    if (err == EAGAIN)
    {
        linux_errno = LINUX_EAGAIN;
    }
    else if (err <= 34)
    {
        // Most of the first 34 errnos are the same
        linux_errno = err;
    }
    else
    {
        printf("errno2linux: Unhandled errno: %d\n", err);
        exit(1);
    }
    return linux_errno;
}

void LinuxKernel::syscallErrnoResult(ucontext_t* ucontext, uint64_t res, bool success, int err)
{
#ifdef DEBUG_RESULT
    log("syscallErrnoResult: res=%d, err=%d", res, err);
#endif

    if (success)
    {
        ucontext->uc_mcontext->__ss.__rax = res;
    }
    else
    {
        int64_t linux_errno = errno2linux(err);
        ucontext->uc_mcontext->__ss.__rax = (uint64_t)(-linux_errno);
#ifdef DEBUG_RESULT
        log("syscallErrnoResult: Returning: %d (%llx)", linux_errno, ucontext->uc_mcontext->__ss.__rax);
#endif
    }
#ifdef DEBUG_RESULT
    log("syscallErrnoResult: Returning: %d", ucontext->uc_mcontext->__ss.__rax);
#endif
}

void LinuxKernel::log(const char* format, ...)
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

    printf("%s: %d: Kernel: %s\n", timeStr, pid, buf);
}

