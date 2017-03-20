
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "kernel.h"
#include "process.h"

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

SYSCALL_METHOD(getpid)
{
    ucontext->uc_mcontext->__ss.__rax = getpid();
    return true;
}

SYSCALL_METHOD(gettid)
{
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);
#ifdef DEBUG
    log("sys_gettid: tid=%lld", tid);
#endif
    ucontext->uc_mcontext->__ss.__rax = tid;
    return true;
}

SYSCALL_METHOD(getuid)
{
    ucontext->uc_mcontext->__ss.__rax = getuid();
    return true;
}

SYSCALL_METHOD(getgid)
{
    ucontext->uc_mcontext->__ss.__rax = getgid();
    return true;
}

SYSCALL_METHOD(geteuid)
{
    ucontext->uc_mcontext->__ss.__rax = geteuid();
    return true;
}

SYSCALL_METHOD(getegid)
{
    ucontext->uc_mcontext->__ss.__rax = getegid();
    return true;
}

SYSCALL_METHOD(getppid)
{
    ucontext->uc_mcontext->__ss.__rax = getppid();
    return true;
}

SYSCALL_METHOD(getpgrp)
{
    ucontext->uc_mcontext->__ss.__rax = getpgrp();
    return true;
}

SYSCALL_METHOD(setpgid)
{
    int pid = ucontext->uc_mcontext->__ss.__rdi;
    int pgid = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
    log("sys_setpgid: pid=%d, pgid=%d\n", pid, pgid);
#endif
    int res = setpgid(pid, pgid);
    int err = errno;
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(set_tid_address)
{
#ifdef DEBUG
    int* tidptr = (int*)ucontext->uc_mcontext->__ss.__rdi;
    log("sys_set_tid_address: tidptr=%p", tidptr);
#endif
    ucontext->uc_mcontext->__ss.__rax = 0;
    return true;
}

SYSCALL_METHOD(getgroups)
{
    int gidsetsize = ucontext->uc_mcontext->__ss.__rdi;
    gid_t* grouplist = (gid_t*)(ucontext->uc_mcontext->__ss.__rsi);
    int res = getgroups(gidsetsize, grouplist);
    int err = errno;
#ifdef DEBUG
    log("sys_getgroups: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res != -1, err);
    return true;
}

SYSCALL_METHOD(getcwd)
{
    char* buf = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    unsigned long size = ucontext->uc_mcontext->__ss.__rsi;

    char* res = getcwd(buf, size);
    int err = errno;

    syscallErrnoResult(ucontext, (uint64_t)res, res != NULL, err);

#ifdef DEBUG
    log("sys_getcwd: buf=%s, err=%d", buf, err);
#endif

    return true;
}

SYSCALL_METHOD(chdir)
{
    const char* filename = (char*)(ucontext->uc_mcontext->__ss.__rdi);
#ifdef DEBUG
    log("sys_chdir: filename=%s\n", filename);
#endif
    int res;
    res = m_fileSystem.chdir(filename);
    syscallErrnoResult(ucontext, res, res == 0, errno);
    return true;
}

SYSCALL_METHOD(fchdir)
{
    int fd = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
    log("sys_fchdir: fd=%d\n", fd);
#endif
    int res;
    res = fchdir(fd);
    syscallErrnoResult(ucontext, res, res == 0, errno);

    return true;
}

SYSCALL_METHOD(chmod)
{
    const char* path = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
    char* osxpath = m_fileSystem.path2osx(path);
    int mode = ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
    log("sys_chmod: path=%p->%p, mode=%d\n", path, osxpath, mode);
#endif
    int res = chmod(osxpath, mode);
    int err = errno;
#ifdef DEBUG
    log("sys_chmod: res=%d, err=%d\n", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

free(osxpath);

    return true;
}

SYSCALL_METHOD(fchmod)
{
    int fd = ucontext->uc_mcontext->__ss.__rdi;
    int mode = ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
    log("sys_fchmod: fd=%d, mode=%d\n", fd, mode);
#endif
    int res = fchmod(fd, mode);
    int err = errno;
#ifdef DEBUG
    log("sys_fchmod: res=%d, err=%d\n", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(umask)
{
    int mask = ucontext->uc_mcontext->__ss.__rdi;

#ifdef DEBUG
    log("sys_umask: mask=%d\n", mask);
#endif

    int res;
    res = umask(mask);
#ifdef DEBUG
    log("sys_umask: res=%d\n", res);
#endif
    ucontext->uc_mcontext->__ss.__rax = res;

    return true;
}

SYSCALL_METHOD(getrlimit)
{
    unsigned int resource = ucontext->uc_mcontext->__ss.__rdi;
    struct rlimit* rlim = (struct rlimit*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
    log("execSyscall: sys_getrlimit: resource=%d, rlim=%p", resource, rlim);
#endif

    if (resource <= 6)
    {
        if (resource == 5)
        {
            resource = RLIMIT_AS;
        }
        if (resource == 6)
        {
            resource = RLIMIT_NPROC;
        }

        int res = getrlimit(resource, rlim);
        int err = errno;
#ifdef DEBUG
        log("sys_getrlimit: res=%d, err=%d\n", res, err);
        log("sys_getrlimit:  -> cur=%lld, max=%lld\n", rlim->rlim_cur, rlim->rlim_max);
#endif
        syscallErrnoResult(ucontext, res, res == 0, err);
    }
    else if (resource == 7)
    {
        //resource = 8;
        rlim->rlim_cur = 500;
        rlim->rlim_max = 500;
        ucontext->uc_mcontext->__ss.__rax = 0;
    }
    else
    {
        log("execSyscall: sys_getrlimit: resource %d not supported\n", resource);
        return false;
    }
    return true;
}

SYSCALL_METHOD(setrlimit)
{
    unsigned int resource = ucontext->uc_mcontext->__ss.__rdi;
    struct rlimit* rlim = (struct rlimit*)(ucontext->uc_mcontext->__ss.__rsi);
    log("execSyscall: sys_setrlimit: resource=%d, rlim->rlim_cur=%lld, rlim_max=%lld", resource, rlim->rlim_cur, rlim->rlim_max);

    ucontext->uc_mcontext->__ss.__rax = 0;

    return true;
}

SYSCALL_METHOD(arch_prctl)
{
    int option = ucontext->uc_mcontext->__ss.__rdi;
    uint64_t addr = (uint64_t)ucontext->uc_mcontext->__ss.__rsi;

    log("sys_arch_prctl: option=0x%x, addr=%llx\n", option, addr);
    log("sys_arch_prctl: Current: fs=0x%llx, gs=0x%llx\n", ucontext->uc_mcontext->__ss.__fs, ucontext->uc_mcontext->__ss.__gs);

    switch (option)
    {
        case ARCH_SET_GS:
            ucontext->uc_mcontext->__ss.__gs = (uint64_t)addr;
            ucontext->uc_mcontext->__ss.__rax = 0;
            break;

        case ARCH_SET_FS:
        {
            m_process->setFS(addr, 1024);
            log("sys_arch_prctl: ARCH_SET_FS=0x%llx\n", addr);
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case ARCH_GET_FS:
            log("sys_arch_prctl: ARCH_GET_FS=0x%llx\n", m_process->getFS());
            ucontext->uc_mcontext->__ss.__rax = m_process->getFS();
            break;

        case ARCH_GET_GS:
            ucontext->uc_mcontext->__ss.__rax = ucontext->uc_mcontext->__ss.__gs;
            ucontext->uc_mcontext->__ss.__rax = 0;
            break;
    }
    return true;
}

SYSCALL_METHOD(exit_group)
{
    int errorCode = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
    log("sys_exit_group: errorCode=%d", errorCode);
#endif

    exit(errorCode);
}

SYSCALL_METHOD(kill)
{
    pid_t pid = ucontext->uc_mcontext->__ss.__rdi;
    int sig = ucontext->uc_mcontext->__ss.__rsi;

    int res = kill(pid, sig);
    int err = errno;

    syscallErrnoResult(ucontext, res, res == 0, err);
    return true;
}

SYSCALL_METHOD(tgkill)
{
    pid_t tgid = ucontext->uc_mcontext->__ss.__rdi;
    pid_t pid = ucontext->uc_mcontext->__ss.__rsi;
    int sig = ucontext->uc_mcontext->__ss.__rdx;

    log("sys_tgkill: tgid=%d, pid=%d, sig=%d\n", tgid, pid, sig);
    return false;
}


