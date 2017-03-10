
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>

#include "kernel.h"
#include "system.h"

SYSCALL_METHOD(uname)
{
    linux_oldutsname* utsname = (linux_oldutsname*)ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
    log("execSyscall: sys_utsname: utsname=%p", utsname);
#endif
    struct utsname osx_utsname;
    uname(&osx_utsname);
    strcpy(utsname->sysname, "Linux");
    strcpy(utsname->nodename, osx_utsname.nodename);
    strcpy(utsname->release, "4.4.24");
    strcpy(utsname->version, "line 4.4.24 (Linux on Mac)"); // The version I've been using as a reference
    strcpy(utsname->machine, osx_utsname.machine);
    ucontext->uc_mcontext->__ss.__rax = 0;
    return true;
}

