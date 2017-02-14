/*
 * This contains the syscalls related to process signalling
 */
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "kernel.h"
//#include "io.h"


SYSCALL_METHOD(rt_sigaction)
{
#ifdef DEBUG
    int sig = ucontext->uc_mcontext->__ss.__rdi;
    void* act = (void*)(ucontext->uc_mcontext->__ss.__rsi);
    void* oact = (void*)(ucontext->uc_mcontext->__ss.__rdx);
    size_t sigsetsize = ucontext->uc_mcontext->__ss.__r10;

    log("execSyscall: sys_rt_sigaction: sig=%d, act=%p, oact=%p, sigsetsize=%lu",
        sig,
        act,
        oact,
        sigsetsize);
#endif
    ucontext->uc_mcontext->__ss.__rax = 0;

    return true;
}

SYSCALL_METHOD(rt_sigprocmask)
{
#ifdef DEBUG
    int how = ucontext->uc_mcontext->__ss.__rdi;
    void* nset = (void*)(ucontext->uc_mcontext->__ss.__rsi);
    void* oset = (void*)(ucontext->uc_mcontext->__ss.__rdx);
    size_t sigsetsize = ucontext->uc_mcontext->__ss.__r10;

    log("execSyscall: sys_rt_sigprocmask: how=%d, nset=%p, oset=%p, sigsetsize=%lu",
        how,
        nset,
        oset,
        sigsetsize);
#endif
    ucontext->uc_mcontext->__ss.__rax = 0;

    return true;
}

SYSCALL_METHOD(rt_sigsuspend)
{
    void* unewset = (void*)(ucontext->uc_mcontext->__ss.__rdi);
    size_t sigsetsize = ucontext->uc_mcontext->__ss.__rsi;
    printf("ElfProcess::execSyscall: sys_rt_sigsuspend: unewset=%p, sigsetsize=%lu\n", unewset, sigsetsize);
    ucontext->uc_mcontext->__ss.__rax = -1;
    while(1)
    {
        sleep(1);
    }

    return true;
}

SYSCALL_METHOD(wait4)
{
    int upid = ucontext->uc_mcontext->__ss.__rdi;
    int* stat_addr = (int*)(ucontext->uc_mcontext->__ss.__rsi);
    int options = ucontext->uc_mcontext->__ss.__rdx;
    void* rusage = (void*)ucontext->uc_mcontext->__ss.__r10;
//#ifdef DEBUG
    log("execSyscall: sys_wait4: upid=%d, stat_addr=%p, options=0x%x, rusage=%p",
        upid,
        stat_addr,
        options,
        rusage);
//#endif

    while (true)
    {
        sleep(1);
    }

/*
    int res = wait4(upid, stat_addr, options, NULL);
    int err = errno;
    log("execSyscall: sys_wait4: res=%d, err=%d", res, err);
    syscallErrnoResult(ucontext, res, res == 0, err);
*/
    return false;
}


