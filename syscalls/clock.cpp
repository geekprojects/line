
#include <time.h>
#include <errno.h>

#include "kernel.h"
#include "clock.h"

SYSCALL_METHOD(nanosleep)
{
    struct timespec *rqtp = (struct timespec*)ucontext->uc_mcontext->__ss.__rdi;
    struct timespec *rmtp = (struct timespec*)ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
    log("sys_nanosleep: rqtp=%p, rmtp=%p", rqtp, rmtp);
#endif
    int res = nanosleep(rqtp, rmtp);
    int err = errno;
#ifdef DEBUG
    log("sys_nanosleep:  -> res=%d, err=%d", res, err);
#endif

    syscallErrnoResult(ucontext, res, res != -1, err);

    return true;
}

SYSCALL_METHOD(clock_gettime)
{
    int linux_clockid = ucontext->uc_mcontext->__ss.__rdi;
    struct timespec *tp = (struct timespec*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
    log("sys_clock_gettime: linux_clockid=%d, tp=%p", linux_clockid, tp);
#endif

    clockid_t clockid = (clockid_t)0;
    switch (linux_clockid)
    {
        case LINUX_CLOCK_REALTIME:
            clockid = CLOCK_REALTIME;
            break;
        default:
            log("sys_clock_gettime: Unmapped clock id: %d", clockid);
            return false;
    }

    int res;
    res = clock_gettime(clockid, tp);
#ifdef DEBUG
    log("sys_clock_gettime:  clockid=%d, res=%d", clockid, res);
#endif
    ucontext->uc_mcontext->__ss.__rax = res;
    return true;
}

SYSCALL_METHOD(time)
{
    time_t* timeptr = (time_t*)(ucontext->uc_mcontext->__ss.__rdi);

time_t t = time(NULL);

//#ifdef DEBUG
    log("sys_time: time=%p", timeptr);
//#endif

if (timeptr != NULL)
{
*timeptr = t;
}

    ucontext->uc_mcontext->__ss.__rax = t;

return true;
}

