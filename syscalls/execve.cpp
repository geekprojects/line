
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "kernel.h"

SYSCALL_METHOD(execve)
{
    char* filename = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    char** orig_argv = (char**)(ucontext->uc_mcontext->__ss.__rsi);
    char** orig_envp = (char**)(ucontext->uc_mcontext->__ss.__rdx);
    log("execSyscall: sys_execve: filename=%s, orig_argv=%p, orig_envp=%p",
        filename,
        orig_argv,
        orig_envp);

    int argc = 0;
    while (orig_argv[argc] != NULL)
    {
        log("execSyscall: sys_execve:  argv[%d]=%s", argc, orig_argv[argc]);
        argc++;
    }

    char** new_argv = new char*[argc + 2];
    new_argv[0] = (char*)"./line";
    int i;
    for (i = 0; i < argc; i++)
    {
        new_argv[i + 1] = orig_argv[i];
    }
    new_argv[argc + 1] = NULL;

    for (i = 0; i < argc + 1; i++)
    {
        log("execSyscall: sys_execve:  new argv[%d]=%s", i, new_argv[i]);
    }

    i = 0;
    while (orig_envp[i] != NULL)
    {
        log("execSyscall: envp[%d]=%s", i, orig_envp[i]);
        i++;
    }
    fflush(stdout);

    execve("./line", new_argv, orig_envp);
    log("execSyscall: sys_execve: execve returned!?");

    return false;
}
