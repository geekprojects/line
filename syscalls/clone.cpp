
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <pthread.h>

#include "kernel.h"
#include "process.h"
#include "thread.h"

bool LinuxKernel::sys_clone_internal(
    ucontext_t* ucontext,
    uint32_t clone_flags,
    uint32_t newsp,
    void* parent_tid,
    void* child_tid,
    void* regs)
{
#ifdef DEBUG
    log(
        "sys_clone_internal: flags=0x%lx, sp=0x%lx, parent_tid=%p, child_tid=%p, regs=%p",
        clone_flags,
        newsp,
        parent_tid,
        child_tid,
        regs);
#endif
    if (clone_flags != 0x1200011)
    {
        log("sys_clone: Unhandled flags: 0x%lx", clone_flags);
    }

    pid_t pid = fork();
    int err = errno;
#ifdef DEBUG
    log( "sys_clone: pid=%d, err=%d", pid, err);
#endif
    fflush(stdout);

    if (pid < 0)
    {
        log("sys_clone: Failed to fork, err=%d",
            err);
        ucontext->uc_mcontext->__ss.__rax = -err;
        exit(255);
    }
    else if (pid == 0)
    {
        // Child
#ifdef DEBUG
        log("sys_clone: Child!");
#endif
        ucontext->uc_mcontext->__ss.__rax = 0;
        if (child_tid != NULL)
        {
            uint64_t tid;
            pthread_threadid_np(NULL, &tid);
#ifdef DEBUG
            log(
                "sys_clone: TID: addr=0x%llx, old=%lld, new=%lld",
                child_tid,
                *((uint64_t*)child_tid),
                tid);
#endif
            *((uint64_t*)child_tid) = tid;
        }
    }
    else
    {
        // Parent
#ifdef DEBUG
        log("sys_clone: Parent!");
#endif
        ucontext->uc_mcontext->__ss.__rax = pid;
    }
    return true;
}

SYSCALL_METHOD(clone)
{
    unsigned long clone_flags = ucontext->uc_mcontext->__ss.__rdi;
    unsigned long newsp = ucontext->uc_mcontext->__ss.__rsi;
    void* parent_tid = (void*)ucontext->uc_mcontext->__ss.__rdx;
    void* child_tid = (void*)ucontext->uc_mcontext->__ss.__r10;
    void* regs = (void*)ucontext->uc_mcontext->__ss.__r8;

    return sys_clone_internal(ucontext, clone_flags, newsp, parent_tid, child_tid, regs);
}


SYSCALL_METHOD(fork)
{
    return sys_clone_internal(ucontext, 0x1200011, 0, 0, NULL, NULL);
}

SYSCALL_METHOD(vfork)
{
    return sys_clone_internal(ucontext, 0x1200011, 0, 0, NULL, NULL);
}

