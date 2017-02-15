
#include <time.h>
#include <errno.h>

#include "kernel.h"
#include "clock.h"

SYSCALL_METHOD(nanosleep)
{
    struct timespec *rqtp = (struct timespec*)ucontext->uc_mcontext->__ss.__rdi;
    struct timespec *rmtp = (struct timespec*)ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
    printf("ElfProcess::execSyscall: sys_nanosleep: rqtp=%p, rmtp=%p\n", rqtp, rmtp);
#endif
    int res = nanosleep(rqtp, rmtp);
    int err = errno;
#ifdef DEBUG
    printf("ElfProcess::execSyscall: sys_nanosleep:  -> res=%d, err=%d\n", res, err);
#endif

    syscallErrnoResult(ucontext, res, res != -1, err);

    return true;
}

SYSCALL_METHOD(clock_gettime)
{
    int linux_clockid = ucontext->uc_mcontext->__ss.__rdi;
    struct timespec *tp = (struct timespec*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
    printf("ElfProcess::execSyscall: sys_clock_gettime: linux_clockid=%d, tp=%p\n", linux_clockid, tp);
#endif

    clockid_t clockid = (clockid_t)0;
    switch (linux_clockid)
    {
        case LINUX_CLOCK_REALTIME:
            clockid = CLOCK_REALTIME;
            break;
        default:
            printf("ElfProcess::execSyscall: sys_clock_gettime: Unmapped clock id: %d\n", clockid);
            return false;
    }

    int res;
    res = clock_gettime(clockid, tp);
#ifdef DEBUG
    printf("ElfProcess::execSyscall: sys_clock_gettime:  clockid=%d, res=%d\n", clockid, res);
#endif
    ucontext->uc_mcontext->__ss.__rax = res;
    return true;
}
