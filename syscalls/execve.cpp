
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include "kernel.h"
#include "thread.h"
#include "process.h"

SYSCALL_METHOD(execve)
{
    char* filename = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    char** orig_argv = (char**)(ucontext->uc_mcontext->__ss.__rsi);
    char** orig_envp = (char**)(ucontext->uc_mcontext->__ss.__rdx);
    log("sys_execve: filename=%s, orig_argv=%p, orig_envp=%p",
        filename,
        orig_argv,
        orig_envp);

    int argc = 0;
    while (orig_argv[argc] != NULL)
    {
        argc++;
    }

    char** new_argv = new char*[argc + 3];

    int i = 0;
    int newarg = 0;
    new_argv[newarg++] = (char*)"./line";
    //new_argv[1] = (char*)"--trace";
    new_argv[newarg++] = (char*)"--forked";
    new_argv[newarg++] = (char*)"--exec";
    new_argv[newarg++] = filename;

    for (i = 0; i < argc; i++, newarg++)
    {
        new_argv[newarg] = orig_argv[i];
    }
    new_argv[newarg] = NULL;

    int res = execve("./line", new_argv, orig_envp);
    int err = errno;

    syscallErrnoResult(ucontext, res, res == 0, err);
    log("sys_execve: execve returned! err=%d", err);

    return true;
}

