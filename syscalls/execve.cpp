
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <mach-o/dyld.h>

#include "kernel.h"
#include "thread.h"
#include "process.h"

SYSCALL_METHOD(execve)
{
    char* filename = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    char** orig_argv = (char**)(ucontext->uc_mcontext->__ss.__rsi);
    char** orig_envp = (char**)(ucontext->uc_mcontext->__ss.__rdx);

#ifdef DEBUG
    log("sys_execve: filename=%s, orig_argv=%p, orig_envp=%p",
        filename,
        orig_argv,
        orig_envp);
#endif

    uint32_t pathlen = 1024;
    char linepath[pathlen];

    int res;
    res = _NSGetExecutablePath(linepath, &pathlen);
    if (res != 0)
    {
        error("sys_execve: Failed to get path to line executable!");
        return false;
    }

    int argc = 0;
    while (orig_argv[argc] != NULL)
    {
        argc++;
    }

    char** new_argv = new char*[argc + 3];

    int i = 0;
    int newarg = 0;
    new_argv[newarg++] = (char*)linepath;
    //new_argv[1] = (char*)"--trace";
    new_argv[newarg++] = (char*)"--forked";
    new_argv[newarg++] = (char*)"--exec";
    new_argv[newarg++] = filename;

    for (i = 0; i < argc; i++, newarg++)
    {
        new_argv[newarg] = orig_argv[i];
    }
    new_argv[newarg] = NULL;

#ifdef DEBUG
    log("sys_execve: linepath=%s, new_argv=%p, orig_envp=%p", linepath, new_argv, orig_envp);
#endif

    log("sys_execve: linepath=%s, elf binary=%s", linepath, filename);

    res = execve(linepath, new_argv, orig_envp);
    int err = errno;

    syscallErrnoResult(ucontext, res, res == 0, err);
    log("sys_execve: execve returned! err=%d", err);

    delete[] new_argv;

    return true;
}

