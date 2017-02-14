
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "kernel.h"
#include "system.h"

SYSCALL_METHOD(uname)
{
    linux_oldutsname* utsname = (linux_oldutsname*)ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
    log("execSyscall: sys_utsname: utsname=%p", utsname);
#endif
    strcpy(utsname->sysname, "Linux");
    strcpy(utsname->nodename, "LinuxOnMac");
    strcpy(utsname->release, "4.4.24");
    strcpy(utsname->version, "4.4.24"); // The version I've been using as a reference
    strcpy(utsname->machine, "x86_64");
    ucontext->uc_mcontext->__ss.__rax = 0;
    return true;
}

