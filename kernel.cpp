
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

LinuxKernel::LinuxKernel(Line* line) : Logger("LinuxKernel")
{
    m_process = NULL;
    m_line = line;
}

LinuxKernel::~LinuxKernel()
{
}

bool LinuxKernel::syscall(uint64_t syscall, ucontext_t* ucontext)
{
    if (syscall >= (sizeof(m_syscalls) / sizeof(syscall_t)))
    {
        log("LinuxKernel::syscall: Invalid syscall: %lld\n", syscall);
        m_process->printregs(ucontext);
        exit(255);
    }
    bool res = (this->*m_syscalls[syscall])(syscall, ucontext);
    if (!res)
    {
        log("LinuxKernel::syscall: syscall failed: %lld", syscall);
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
        int64_t linux_errno = err;

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
            error("syscallErrnoResult: Unhandled errno: %d", err);
            exit(1);
        }

        ucontext->uc_mcontext->__ss.__rax = (uint64_t)(-linux_errno);
#ifdef DEBUG_RESULT
        log("syscallErrnoResult: Returning: %d (%llx)", linux_errno, ucontext->uc_mcontext->__ss.__rax);
#endif
    }
#ifdef DEBUG_RESULT
    log("syscallErrnoResult: Returning: %d", ucontext->uc_mcontext->__ss.__rax);
#endif
}

