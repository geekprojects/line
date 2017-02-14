
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include "kernel.h"
#include "futex.h"

SYSCALL_METHOD(futex)
{
    uint32_t* uaddr = (uint32_t*)ucontext->uc_mcontext->__ss.__rdi;
    int op = ucontext->uc_mcontext->__ss.__rsi;
    uint32_t val = ucontext->uc_mcontext->__ss.__rdx;
    //void* utime = (void*)ucontext->uc_mcontext->__ss.__r10;
    //uint32_t* uaddr2 = (uint32_t*)ucontext->uc_mcontext->__ss.__r8;
    //uint32_t val3 = ucontext->uc_mcontext->__ss.__r9;

#ifdef DEBUG
    log(
        "execSyscall: sys_futex: 0x%llx: uaddr=%p (%d), op=%d, val=%d",
        ucontext->uc_mcontext->__ss.__rip,
        uaddr,
        *uaddr,
        op,
        val);
#endif

    int cmd = op & FUTEX_CMD_MASK;

    if (cmd == FUTEX_WAIT)
    {
        //uint32_t val = *uaddr;
        log("execSyscall: sys_futex: FUTEX_WAIT: val=%d", val);
        exit(255);
    }
    else if (cmd == FUTEX_WAKE)
    {
#ifdef DEBUG
        uint32_t val = *uaddr;
        log("execSyscall: sys_futex: FUTEX_WAKE: val=%d", val);
#endif
    }
    else
    {
        log("execSyscall: sys_futex: uaddr value=0x%x", *uaddr);
        exit(255);
    }
    ucontext->uc_mcontext->__ss.__rax = 0;

    return true;
}

