#ifndef __LINE_LINUX_KERNEL_H_
#define __LINE_LINUX_KERNEL_H_

#include <sys/ucontext.h>
#include <stdint.h>
#include <dirent.h>

#include <map>

#include "filesystem.h"
#include "logger.h"

#define LINUX_EAGAIN 11

struct LinuxSocket
{
    int fd;
    int family;
    int type;
    int protocol;
};

class LinuxKernel;
class LineProcess;
typedef bool(LinuxKernel::*syscall_t)(uint64_t syscall, ucontext_t* ucontext);

#define SYSCALL_DEFINE(_name) bool sys_ ## _name(uint64_t syscall, ucontext_t* ucontext)
#define SYSCALL_METHOD(_name) bool LinuxKernel::sys_ ## _name(uint64_t syscall, ucontext_t* ucontext)

class LinuxKernel : Logger
{
 private:
    FileSystem m_fileSystem;
    LineProcess* m_process;

    std::map<int, LinuxSocket*> m_sockets;
    std::map<int, DIR*> m_dirs;

    static syscall_t m_syscalls[];

    void syscallErrnoResult(ucontext_t* ucontext, uint64_t res, bool success, int err);

 public:
    LinuxKernel(LineProcess* process);
    ~LinuxKernel();

    FileSystem* getFileSystem() { return &m_fileSystem; }

    bool syscall(uint64_t syscall, ucontext_t* ucontext);

    SYSCALL_DEFINE(notimplemented);

    SYSCALL_DEFINE(read);
    SYSCALL_DEFINE(write);
    SYSCALL_DEFINE(open);
    SYSCALL_DEFINE(close);
    SYSCALL_DEFINE(stat);
    SYSCALL_DEFINE(fstat);
    SYSCALL_DEFINE(lstat);
    SYSCALL_DEFINE(lseek);
    SYSCALL_DEFINE(mmap);
    SYSCALL_DEFINE(mprotect);
    SYSCALL_DEFINE(munmap);
    SYSCALL_DEFINE(brk);
    SYSCALL_DEFINE(rt_sigaction);
    SYSCALL_DEFINE(rt_sigprocmask);
    SYSCALL_DEFINE(ioctl);
    SYSCALL_DEFINE(writev);
    SYSCALL_DEFINE(access);
    SYSCALL_DEFINE(pipe);
    SYSCALL_DEFINE(select);
    SYSCALL_DEFINE(msync);
    SYSCALL_DEFINE(mincore);
    SYSCALL_DEFINE(dup);
    SYSCALL_DEFINE(dup2);
    SYSCALL_DEFINE(nanosleep);
    SYSCALL_DEFINE(getpid);
    SYSCALL_DEFINE(socket);
    SYSCALL_DEFINE(connect);
    SYSCALL_DEFINE(clone);
    SYSCALL_DEFINE(execve);
    SYSCALL_DEFINE(wait4);
    SYSCALL_DEFINE(kill);
    SYSCALL_DEFINE(uname);
    SYSCALL_DEFINE(fcntl);
    SYSCALL_DEFINE(fsync);
    SYSCALL_DEFINE(ftruncate);
    SYSCALL_DEFINE(getdents);
    SYSCALL_DEFINE(getcwd);
    SYSCALL_DEFINE(chdir);
    SYSCALL_DEFINE(fchdir);
    SYSCALL_DEFINE(rename);
    SYSCALL_DEFINE(mkdir);
    SYSCALL_DEFINE(creat);
    SYSCALL_DEFINE(link);
    SYSCALL_DEFINE(unlink);
    SYSCALL_DEFINE(readlink);
    SYSCALL_DEFINE(chmod);
    SYSCALL_DEFINE(fchmod);
    SYSCALL_DEFINE(umask);
    SYSCALL_DEFINE(getrlimit);
    SYSCALL_DEFINE(getuid);
    SYSCALL_DEFINE(getgid);
    SYSCALL_DEFINE(geteuid);
    SYSCALL_DEFINE(getegid);
    SYSCALL_DEFINE(setpgid);
    SYSCALL_DEFINE(getppid);
    SYSCALL_DEFINE(getpgrp);
    SYSCALL_DEFINE(getgroups);
    SYSCALL_DEFINE(rt_sigsuspend);
    SYSCALL_DEFINE(sigaltstack);
    SYSCALL_DEFINE(statfs);
    SYSCALL_DEFINE(mlock);
    SYSCALL_DEFINE(arch_prctl);
    SYSCALL_DEFINE(setrlimit);
    SYSCALL_DEFINE(gettid);
    SYSCALL_DEFINE(getxattr);
    SYSCALL_DEFINE(futex);
    SYSCALL_DEFINE(set_tid_address);
    SYSCALL_DEFINE(fadvise64);
    SYSCALL_DEFINE(clock_gettime);
    SYSCALL_DEFINE(exit_group);
    SYSCALL_DEFINE(tgkill);
    SYSCALL_DEFINE(utimes);
    SYSCALL_DEFINE(openat);
};

#endif
