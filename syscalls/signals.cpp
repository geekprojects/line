/*
 * This contains the syscalls related to process signalling
 */
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "kernel.h"
#include "signals.h"


SYSCALL_METHOD(rt_sigaction)
{
#ifdef DEBUG
    int sig = ucontext->uc_mcontext->__ss.__rdi;
    void* act = (void*)(ucontext->uc_mcontext->__ss.__rsi);
    void* oact = (void*)(ucontext->uc_mcontext->__ss.__rdx);
    size_t sigsetsize = ucontext->uc_mcontext->__ss.__r10;

    log("sys_rt_sigaction: sig=%d, act=%p, oact=%p, sigsetsize=%lu",
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

    log("sys_rt_sigprocmask: how=%d, nset=%p, oset=%p, sigsetsize=%lu",
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
    log("sys_rt_sigsuspend: unewset=%p, sigsetsize=%lu\n", unewset, sigsetsize);
    ucontext->uc_mcontext->__ss.__rax = -1;
    while(1)
    {
        sleep(1);
    }

    return true;
}

SYSCALL_METHOD(sigaltstack)
{
    linux_stack_t* linux_uss = (linux_stack_t*)(ucontext->uc_mcontext->__ss.__rdi);
    linux_stack_t* linux_uoss = (linux_stack_t*)ucontext->uc_mcontext->__ss.__rsi;
    log("sys_sigaltstack: linux_uss=%p, linux_uoss=%p", linux_uss, linux_uoss);

    ucontext->uc_mcontext->__ss.__rax = 0;

/*
    if (linux_uss != NULL)
    {
        return false;
    }

    stack_t osx_uoss;
    int res = sigaltstack(NULL, &osx_uoss);
    int err = errno;

    if (res == 0)
    {
        linux_uoss->ss_sp = osx_uoss.ss_sp;
        linux_uoss->ss_size = osx_uoss.ss_size;
        linux_uoss->ss_flags = 0;
        if (osx_uoss.ss_flags & SS_ONSTACK)
        {
            linux_uoss->ss_flags |= LINUX_SS_ONSTACK;
        }
        if (osx_uoss.ss_flags & SS_DISABLE)
        {
            linux_uoss->ss_flags |= LINUX_SS_DISABLE;
        }
    }

    syscallErrnoResult(ucontext, res, res == 0, err);
    log("sys_sigaltstack: res=%d, err=%d", res, err);
*/

    return true;
}

SYSCALL_METHOD(wait4)
{
    int upid = ucontext->uc_mcontext->__ss.__rdi;
    int* stat_addr = (int*)(ucontext->uc_mcontext->__ss.__rsi);
    int linux_options = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
    void* rusage = (void*)ucontext->uc_mcontext->__ss.__r10;
#endif

    int osx_options = 0;
    if (linux_options & LINUX_WNOHANG)
    {
        osx_options |= WNOHANG;
    }
    if (linux_options & LINUX_WUNTRACED)
    {
        osx_options |= WUNTRACED;
    }
    if (linux_options & LINUX_WSTOPPED)
    {
        osx_options |= WSTOPPED;
    }
    if (linux_options & LINUX_WEXITED)
    {
        osx_options |= WEXITED;
    }
    if (linux_options & LINUX_WCONTINUED)
    {
        osx_options |= WCONTINUED;
    }
    if (linux_options & LINUX_WNOWAIT)
    {
        osx_options |= WNOWAIT;
    }

#ifdef DEBUG
    log("sys_wait4: upid=%d, stat_addr=%p, options=0x%x (0x%x), rusage=%p",
        upid,
        stat_addr,
        linux_options,
        osx_options,
        rusage);
#endif
    //ucontext->uc_mcontext->__ss.__rax = -1;


    int res = wait4(upid, stat_addr, osx_options, NULL);
    int err = errno;

#ifdef DEBUG
    log("execSyscall: sys_wait4: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res != -1, err);

    return true;
}


