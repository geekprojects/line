/*
 * line - Line Is Not an Emulator
 * Copyright (C) 2016 GeekProjects.com
 *
 * This file is part of line.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include <pthread.h>

#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>

#include "elfprocess.h"
#include "linux/syscall.h"
#include "linux/term.h"
#include "utils.h"

#ifndef DEBUG
#define DEBUG
#endif

using namespace std;

void stat2linux(struct stat osx_stat, struct linux_stat* linux_stat)
{
    memset(linux_stat, 0, sizeof(struct linux_stat));
    linux_stat->st_dev = osx_stat.st_dev;         /* Device.  */
    linux_stat->st_ino = osx_stat.st_ino;         /* File serial number.  */
    linux_stat->st_mode = osx_stat.st_mode;        /* File mode.  */
    linux_stat->st_nlink = osx_stat.st_nlink;       /* Link count.  */
    linux_stat->st_uid = osx_stat.st_uid;         /* User ID of the file's owner.  */
    linux_stat->st_gid = osx_stat.st_gid;         /* Group ID of the file's group. */
    linux_stat->st_rdev = osx_stat.st_rdev;        /* Device number, if device.  */
    linux_stat->st_size = osx_stat.st_size;        /* Size of file, in bytes.  */
    linux_stat->st_blksize = osx_stat.st_blksize;     /* Optimal block size for I/O.  */
    linux_stat->st_blocks = osx_stat.st_blocks;      /* Number 512-byte blocks allocated. */
    linux_stat->st_atime_ = osx_stat.st_atime;       /* Time of last access.  */
    linux_stat->st_atime_nsec = 0;
    linux_stat->st_mtime_ = osx_stat.st_mtime;       /* Time of last modification.  */
    linux_stat->st_mtime_nsec = 0;
    linux_stat->st_ctime_ = osx_stat.st_ctime;       /* Time of last status change.  */
    linux_stat->st_ctime_nsec = 0;
}

int oflags2osx(int linux_flags)
{
    int osx_flags = 0;

    if (!!(linux_flags & LINUX_O_WRONLY))
    {
        osx_flags |= O_WRONLY;
    }
    if (!!(linux_flags & LINUX_O_RDWR))
    {
        osx_flags |= O_RDWR;
    }
    if (!!(linux_flags & LINUX_O_CREAT))
    {
        osx_flags |= O_CREAT;
    }
    if (!!(linux_flags & LINUX_O_EXCL))
    {
        osx_flags |= O_EXCL;
    }
    if (!!(linux_flags & LINUX_O_NOCTTY))
    {
        osx_flags |= O_NOCTTY;
    }
    if (!!(linux_flags & LINUX_O_TRUNC))
    {
        osx_flags |= O_TRUNC;
    }
    if (!!(linux_flags & LINUX_O_APPEND))
    {
        osx_flags |= O_APPEND;
    }
    if (!!(linux_flags & LINUX_O_NONBLOCK))
    {
        osx_flags |= O_NONBLOCK;
    }
    if (!!(linux_flags & LINUX_O_DSYNC))
    {
        osx_flags |= O_DSYNC;
    }
    if (!!(linux_flags & LINUX_O_DIRECTORY))
    {
        osx_flags |= O_DIRECTORY;
    }

    return osx_flags;
}

int errno2linux(int err)
{
    int linux_errno = err;

    if (err == EAGAIN)
    {
        linux_errno = LINUX_EAGAIN;
    }
    else if (err <= 34)
    {
        // Most of the first 34 errnos are the same
        linux_errno = err;
    }
    else
    {
        printf("ElfProcess::errno2linux: Unhandled errno: %d\n", err);
        exit(1);
    }
    return linux_errno;
}

void ElfProcess::syscallErrnoResult(ucontext_t* ucontext, uint64_t res, bool success, int err)
{
#ifdef DEBUG_RESULT
    log("syscallErrnoResult: res=%d, err=%d", res, err);
#endif

    if (success)
    {
        ucontext->uc_mcontext->__ss.__rax = res;
    }
    else
    {
        int64_t linux_errno = errno2linux(err);
        ucontext->uc_mcontext->__ss.__rax = (uint64_t)(-linux_errno);
#ifdef DEBUG_RESULT
        log("syscallErrnoResult: Returning: %d (%llx)", linux_errno, ucontext->uc_mcontext->__ss.__rax);
#endif
    }
#ifdef DEBUG_RESULT
    log("syscallErrnoResult: Returning: %d", ucontext->uc_mcontext->__ss.__rax);
#endif
}

bool ElfProcess::execSyscall(uint64_t syscall, ucontext_t* ucontext)
{
    errno = 0;

    switch (syscall)
    {
        case 0x0: // sys_read
        {
            unsigned int fd = (ucontext->uc_mcontext->__ss.__rdi);
            const char* buf = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
            size_t count = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
            log("execSyscall: sys_read: fd=%d, buf=%p, count=%lu", fd, buf, count);
#endif
            int res = read(fd, (void*)buf, count);
            int err = errno;
            syscallErrnoResult(ucontext, res, res >= 0, err);
        } break;

        case 0x1: // write
        {
            unsigned int fd = (ucontext->uc_mcontext->__ss.__rdi);
            const char* buf = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
            size_t count = ucontext->uc_mcontext->__ss.__rdx;

#ifdef DEBUG
            log("execSyscall: sys_write: fd=%d, buf=%p, count=%lu", fd, buf, count);
#endif

            int res = write(fd, buf, count);
            int err = errno;
            syscallErrnoResult(ucontext, res, res >= 0, err);
        } break;

        case 0x2: // open
        {
            const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            int flags = ucontext->uc_mcontext->__ss.__rsi;
            int mode = ucontext->uc_mcontext->__ss.__rdx;
            int osx_flags = oflags2osx(flags);
#ifdef DEBUG
            log("execSyscall: sys_open: filename=%s, flags=0x%x (0x%x), mode=0x%x", filename, flags, osx_flags, mode);
#endif

            int res = m_fileSystem.openat(AT_FDCWD, filename, osx_flags, mode);
            int err = errno;
#ifdef DEBUG
            log("execSyscall: sys_open: res=%d, errno=%d", res, err);
#endif
            syscallErrnoResult(ucontext, res, res >= 0, err);
        } break;

        case 0x3: // sys_close
        {
            unsigned int fd = (ucontext->uc_mcontext->__ss.__rdi);

#ifdef DEBUG
            log("execSyscall: sys_close: fd=%u", fd);
#endif
            if (fd > 2)
            {
                int res = close(fd);
                syscallErrnoResult(ucontext, res, res == 0, errno);
            }
            else
            {
#ifdef DEBUG
                log("execSyscall: sys_close: fd=%u, STDOUT/IN/ERR", fd);
#endif
                ucontext->uc_mcontext->__ss.__rax = 0;
            }
        } break;

        case 0x4: // sys_stat
        {
            const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            log("execSyscall: sys_stat: filename=%s, linux_stat=%p", filename, linux_stat);
#endif

            char* osx_filename = m_fileSystem.path2osx(filename);

            struct stat osx_stat;
            int res;
            res = stat(osx_filename, &osx_stat);
            int err = errno;

            if (res == 0)
            {
                stat2linux(osx_stat, linux_stat);
            }
            syscallErrnoResult(ucontext, res, res == 0, err);

            free(osx_filename);

#ifdef DEBUG
            log("execSyscall: sys_stat: res=%d", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x5: // sys_fstat
        {
            uint64_t fd = ucontext->uc_mcontext->__ss.__rdi;
            linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            log("execSyscall: sys_fstat: fd=%lld, linux_stat=%p", fd, linux_stat);
#endif

            struct stat osx_stat;
            int res = fstat(fd, &osx_stat);
            int err = errno;

            if (res == 0)
            {
                stat2linux(osx_stat, linux_stat);
            }
            syscallErrnoResult(ucontext, res, res == 0, err);

#ifdef DEBUG
            log("execSyscall: sys_fstat: res=%d", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x6: // sys_lstat
        {
            const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            log("execSyscall: sys_lstat: filename=%s, linux_stat=%p", filename, linux_stat);
#endif

            struct stat osx_stat;
            int res;
            res = lstat(filename, &osx_stat);
            int err = errno;

            if (res == 0)
            {
                stat2linux(osx_stat, linux_stat);
            }
            syscallErrnoResult(ucontext, res, res == 0, err);

#ifdef DEBUG
            log("execSyscall: sys_lstat: res=%d", res);
#endif
        } break;

        case 0x8: // sys_lseek
        {
            unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t offset = ucontext->uc_mcontext->__ss.__rsi;
            unsigned int origin = ucontext->uc_mcontext->__ss.__rdx;

#ifdef DEBUG
            log("execSyscall: sys_lseek: fd=%d, offset=%lld, origin=%d", fd, offset, origin);
#endif
            int64_t res = lseek(fd, offset, origin);
            int err = errno;
#ifdef DEBUG
            log("execSyscall: sys_lseek: -> res=%lld, err=%d", res, err);
#endif
            syscallErrnoResult(ucontext, res, res >=0, err);
        } break;

        case 0x9: // sys_mmap
        {
            uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
            uint64_t prot = ucontext->uc_mcontext->__ss.__rdx;
            uint64_t flags = ucontext->uc_mcontext->__ss.__r10;
            uint64_t fd = ucontext->uc_mcontext->__ss.__r8;
            uint64_t off = ucontext->uc_mcontext->__ss.__r9;

            int darwinFlags = 0;

            if (flags & LINUX_MAP_SHARED)
            {
                darwinFlags |= MAP_SHARED;
            }
            if (flags & LINUX_MAP_PRIVATE)
            {
                darwinFlags |= MAP_PRIVATE;
            }
            if (flags & LINUX_MAP_FIXED)
            {
                darwinFlags |= MAP_FIXED;
            }
            if (flags & LINUX_MAP_ANONYMOUS)
            {
                darwinFlags |= MAP_ANON;
                fd = 0;
            }
            if (flags & LINUX_MAP_NORESERVE)
            {
                darwinFlags |= MAP_NORESERVE;
            }
            prot &= 0x7;
#ifdef DEBUG
            log(
                "execSyscall: sys_mmap: addr=0x%llx, len=%llu, prot=0x%llx, flags=0x%llx->%x, fd=%lld, off=%lld",
                addr,
                len,
                prot,
                flags,
                darwinFlags,
                fd,
                off);
#endif
            void* result = mmap((void*)addr, len, prot, darwinFlags, fd, off);
            int err = errno;
#ifdef DEBUG
            log("execSyscall: sys_mmap: -> result=%p, errno=%d", result, err);
#endif
            syscallErrnoResult(ucontext, (uint64_t)result, result != NULL, err);
        } break;

        case 0xa: // sys_mprotect
        {
            uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
            uint64_t prot = ucontext->uc_mcontext->__ss.__rdx & 7; // Only the RWX flags
#ifdef DEBUG
            log("execSyscall: sys_mprotext: addr=0x%llx, len=%llu, prot=0x%llx", addr, len, prot);
#endif

            int res = mprotect((void*)addr, len, prot);
            int err = errno;
#ifdef DEBUG
            log("execSyscall: sys_mprotext:  -> res=%d", res);
#endif
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;

        case 0xb: // sys_munmap
        {
            uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
            log("execSyscall: sys_munmap: addr=0x%llx, len=%llu", addr, len);
#endif

            int res = munmap((void*)addr, len);

#ifdef DEBUG
            log("execSyscall: sys_munmap: -> res=%d", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = (uint64_t)res;
        } break;

        case 0xc: // sys_brk
        {
            uint64_t brkarg = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
            log("execSyscall: sys_brk: brkarg=0x%llx", brkarg);
#endif

            if (brkarg == 0)
            {
                ucontext->uc_mcontext->__ss.__rax = (uint64_t)m_brk;
            }
            else
            {
                uint64_t newbrk = ALIGN(brkarg, 4096);
                uint64_t len = newbrk - m_brk;
#ifdef DEBUG
                log("execSyscall: sys_brk: newbrk=0x%llx, len=%llx", newbrk, len);
#endif
                void* maddr = mmap((void*)m_brk, len,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_FIXED | MAP_ANON | MAP_PRIVATE,
                    -1,
                    0);
                int err = errno;
#ifdef DEBUG
                log("execSyscall: sys_brk:  -> maddr=%p, errno=%d", maddr, err);
#endif
                syscallErrnoResult(ucontext, newbrk, maddr != NULL, err);
            }
#ifdef DEBUG
            log("execSyscall: sys_brk: returning: 0x%llx", ucontext->uc_mcontext->__ss.__rax);
#endif

        } break;

        case 0xd: // sys_rt_sigaction
        {
#ifdef DEBUG
            int sig = ucontext->uc_mcontext->__ss.__rdi;
            void* act = (void*)(ucontext->uc_mcontext->__ss.__rsi);
            void* oact = (void*)(ucontext->uc_mcontext->__ss.__rdx);
            size_t sigsetsize = ucontext->uc_mcontext->__ss.__r10;

            log("execSyscall: sys_rt_sigaction: sig=%d, act=%p, oact=%p, sigsetsize=%lu",
                sig,
                act,
                oact,
                sigsetsize);
#endif
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0xe: // sys_rt_sigprocmask
        {
#ifdef DEBUG
            int how = ucontext->uc_mcontext->__ss.__rdi;
            void* nset = (void*)(ucontext->uc_mcontext->__ss.__rsi);
            void* oset = (void*)(ucontext->uc_mcontext->__ss.__rdx);
            size_t sigsetsize = ucontext->uc_mcontext->__ss.__r10;

            log("execSyscall: sys_rt_sigprocmask: how=%d, nset=%p, oset=%p, sigsetsize=%lu",
                how,
                nset,
                oset,
                sigsetsize);
#endif
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0x10: // sys_ioctl
        {
            unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
            unsigned int cmd = ucontext->uc_mcontext->__ss.__rsi;
            unsigned long arg = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
            log("execSyscall: sys_ioctl: fd=%d, cmd=0x%x, arg=0x%lx", fd, cmd, arg);
#endif

            if (fd > 2)
            {
                printf("ElfProcess::execSyscall: sys_ioctl:  -> Only supported for fd 1\n");
                exit(1);
            }
            switch (cmd)
            {
                case LINUX_TCGETS:
                {
#ifdef DEBUG
                    struct termios* t = (struct termios*)arg;
                    printf("ElfProcess::execSyscall: sys_ioctl: TCGETS: iflag=0x%x, oflag=0x%x, cflag=0x%x, lflag=0x%x\n",
                        t->c_iflag,
                        t->c_oflag,
                        t->c_cflag,
                        t->c_lflag);
#endif
                    ucontext->uc_mcontext->__ss.__rax = 0;
                } break;

                case LINUX_TIOCGWINSZ:
                {
#ifdef DEBUG
                    printf("ElfProcess::execSyscall: sys_ioctl: TIOCGWINSZ\n");
#endif
                    struct linux_winsize* ws = (struct linux_winsize*)arg;
                    ws->ws_row = 25;
                    ws->ws_col = 80;
                    ucontext->uc_mcontext->__ss.__rax = 0;
                } break;

                case LINUX_TIOCGPGRP:
                {
                    int res;
                    pid_t pgrp;
                    res = ioctl(fd, TIOCGPGRP, &pgrp);
                    int err = errno;
                    pid_t* argptr = (pid_t*)arg;
                    *argptr = pgrp;
                    syscallErrnoResult(ucontext, res, res >= 0, err);
                } break;

                case LINUX_TIOCSPGRP:
                {
                    int res;

                    res = ioctl(fd, TIOCGPGRP, &arg);
                    int err = errno;
                    syscallErrnoResult(ucontext, res, res >= 0, err);
                } break;

                default:
                    printf("ElfProcess::execSyscall: sys_ioctl: Unknown ioctl: 0x%x\n", cmd);
                    exit(1);
                    break;
            }
        } break;

        case 0x14: // sys_writev
        {
            int fd = ucontext->uc_mcontext->__ss.__rdi;
            iovec* vec = (iovec*)(ucontext->uc_mcontext->__ss.__rsi);
            unsigned long vlen = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
            printf("ElfProcess::execSyscall:  -> sys_writev: fd=%d, vec=%p (%p, %lu), vlen=%lu\n", fd, vec, vec->iov_base, vec->iov_len, vlen);
#endif

            ssize_t res = writev(fd, vec, vlen);
#ifdef DEBUG
            printf("ElfProcess::execSyscall:  -> sys_writev: res=%lu\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x15: // sys_access
        {
            const char* path = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            int mode = (int)(ucontext->uc_mcontext->__ss.__rsi);

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_access: path=%s, mode=0x%x\n", path, mode);
#endif
            int res = m_fileSystem.access(path, mode);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_access:  -> res=%d\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x16: // sys_pipe
        {
            int* filedes = (int*)(ucontext->uc_mcontext->__ss.__rdi);

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_pipe: filedes=%p\n", filedes);
#endif
            int res = pipe(filedes);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_pipe: res=%d, errno=%d\n", res, err);
#endif

            syscallErrnoResult(ucontext, res, res != -1, err);
        } break;

        case 0x17: // sys_select
        {
            int nfds = ucontext->uc_mcontext->__ss.__rdi;
            fd_set* readfds = (fd_set*)(ucontext->uc_mcontext->__ss.__rsi);
            fd_set* writefds = (fd_set*)(ucontext->uc_mcontext->__ss.__rdx);
            fd_set* errorfds = (fd_set*)(ucontext->uc_mcontext->__ss.__r10);
            struct timeval* timeout = (struct timeval*)(ucontext->uc_mcontext->__ss.__r8);

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_select: nfds=%d, readfds=%p, writefds=%p, errorfds=%p, timeout=%p\n",
                nfds,
                readfds,
                writefds,
                errorfds,
                timeout);
#endif
            int res = select(nfds, readfds, writefds, errorfds, timeout);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_select: res=%d, errno=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res != -1, err);
        } break;

        case 0x1a: // sys_msync
        {
            void* addr = (void*)(ucontext->uc_mcontext->__ss.__rdi);
            size_t len = ucontext->uc_mcontext->__ss.__rsi;
            int flags = ucontext->uc_mcontext->__ss.__rdx;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_msync: addr=%p, len=%ld, flags=%d\n", addr, len, flags);
#endif
            int res = msync(addr, len, flags);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_msync: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;

        case 0x1b: // sys_mincore
        {
            unsigned long start = ucontext->uc_mcontext->__ss.__rdi;
            size_t len = ucontext->uc_mcontext->__ss.__rsi;
            char* vec = (char*)(ucontext->uc_mcontext->__ss.__rdx);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_mincore: start=0x%lx, len=%ld, vec=%p\n", start, len, vec);
#endif
            int res;
            res = mincore((void*)start, len, vec);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_mincore: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res != -1, err);
        } break;

        case 0x20: // sys_dup
        {
            int filedes = ucontext->uc_mcontext->__ss.__rdi;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_dup: fd=%d\n", filedes);
#endif

            int res = dup(filedes);
            int err = errno;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_dup: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res != -1, err);
        } break;

        case 0x21: // sys_dup2
        {
            int filedes = ucontext->uc_mcontext->__ss.__rdi;
            int newfd = ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_dup2: fd=%d, newfd=%d\n", filedes, newfd);
#endif

            int res = newfd;
            int err = 0;
/*
            int res = dup2(filedes, newfd);
            int err = errno;
*/

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_dup2: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res != -1, err);
        } break;


        case 0x23: // sys_nanosleep
        {
            struct timespec *rqtp = (struct timespec*)ucontext->uc_mcontext->__ss.__rdi;
            struct timespec *rmtp = (struct timespec*)ucontext->uc_mcontext->__ss.__rsi;
    
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_nanosleep: rqtp=%p, rmtp=%p\n", rqtp, rmtp);
#endif
            int res;
            res = nanosleep(rqtp, rmtp);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_nanosleep:  -> res=%d\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x27: // sys_getpid
        {
            ucontext->uc_mcontext->__ss.__rax = getpid();
        } break;

        case 0x29: // sys_socket
        {
            int family = ucontext->uc_mcontext->__ss.__rdi;
            int type = ucontext->uc_mcontext->__ss.__rsi;
            int protocol = ucontext->uc_mcontext->__ss.__rdx;
            int osx_type = type & 0xf;
            printf(
                "ElfProcess::execSyscall: sys_socket: family=0x%x, type=0x%x (0x%x), protocol=0x%x\n",
                family,
                type,
                osx_type,
                protocol);
            if (family != 1)
            {
                printf("ElfProcess::execSyscall: sys_socket: Unsupported family=0x%x\n", family);
                exit(255);
            }

            if (osx_type != 1)
            {
                printf("ElfProcess::execSyscall: sys_socket: Unsupported PF_UNIX type=0x%x\n", osx_type);
                exit(255);
            }

            if (protocol != 0)
            {
                printf("ElfProcess::execSyscall: sys_socket: Unsupported PF_UNIX protocol=0x%x\n", protocol);
                exit(255);
            }

            int res;
            res = socket(family, osx_type, protocol);
            int err = errno;
            printf("ElfProcess::execSyscall: sys_socket: res=%d, err=%d\n", res, err);
            syscallErrnoResult(ucontext, res, res != -1, err);

            if (res != -1)
            {
                // Keep track of this socket
                LinuxSocket* socket = new LinuxSocket();
                socket->fd = res;
                socket->family = family;
                socket->type = osx_type;
                socket->protocol = protocol;
                m_sockets.insert(make_pair(res, socket));
            }
        } break;

        case 0x2a: // sys_connect
        {
            int fd = ucontext->uc_mcontext->__ss.__rdi;
            void* addr = (void*)(ucontext->uc_mcontext->__ss.__rsi);
            int addrlen = ucontext->uc_mcontext->__ss.__rdx;

            printf(
                "ElfProcess::execSyscall: sys_connect: fd=%d, addr=%p, addrlen=%d\n",
                fd,
                addr,
                addrlen);

            map<int, LinuxSocket*>::iterator it = m_sockets.find(fd);
            if (it != m_sockets.end())
            {
                LinuxSocket* socket = it->second;

                if (socket->family != PF_UNIX)
                {
                    printf(
                        "ElfProcess::execSyscall: sys_connect: Unexpected socket family: %d\n",
                        socket->family);
                    exit(255);
                }
                if (addrlen != sizeof(linux_sockaddr_un))
                {
                    printf(
                        "ElfProcess::execSyscall: sys_connect: Unexpected addrlen: %d\n",
                        addrlen);
                    exit(255);
                }
                linux_sockaddr_un* linux_sockaddr = (linux_sockaddr_un*)addr;
                printf(
                    "ElfProcess::execSyscall: sys_connect: path: %s\n",
                    linux_sockaddr->sun_path);

                sockaddr_un osx_sockaddr;
                osx_sockaddr.sun_len = addrlen;
                osx_sockaddr.sun_family = linux_sockaddr->sun_family;
                strncpy(osx_sockaddr.sun_path, linux_sockaddr->sun_path, 104);

                int res = connect(fd, (sockaddr*)&osx_sockaddr, sizeof(osx_sockaddr));
                int err = errno;
                printf("ElfProcess::execSyscall: sys_connect: res=%d, err=%d\n", res, err);
                syscallErrnoResult(ucontext, res, res == 0, err);

            }
            else
            {
                printf(
                    "ElfProcess::execSyscall: sys_connect: Unable to find socket for fd: %d\n",
                    fd);
            }
        } break;

        case 0x38: // sys_clone
        {
            unsigned long clone_flags = ucontext->uc_mcontext->__ss.__rdi;
            unsigned long newsp = ucontext->uc_mcontext->__ss.__rsi;
            void* parent_tid = (void*)ucontext->uc_mcontext->__ss.__rdx;
            void* child_tid = (void*)ucontext->uc_mcontext->__ss.__r10;
            void* regs = (void*)ucontext->uc_mcontext->__ss.__r8;

            log(
                "execSyscall: sys_clone: flags=0x%lx, sp=0x%lx, parent_tid=%p, child_tid=%p, regs=%p",
                clone_flags,
                newsp,
                parent_tid,
                child_tid,
                regs);
            if (clone_flags != 0x1200011)
            {
                log("execSyscall: sys_clone: Unhandled flags: 0x%lx", clone_flags);
            }

            fflush(stdout);

            pid_t pid = fork();
            int err = errno;
            log( "execSyscall: sys_clone: pid=%d, err=%d", pid, err);

            if (pid < 0)
            {
                log("execSyscall: sys_clone: Failed to fork, err=%d",
                    err);
                ucontext->uc_mcontext->__ss.__rax = -err;
                exit(255);
            }
            else if (pid == 0)
            {
                // Child
                log("execSyscall: sys_clone: Child!");
                ucontext->uc_mcontext->__ss.__rax = 0;
                if (child_tid != NULL)
                {
                    uint64_t tid;
                    pthread_threadid_np(NULL, &tid);
                    log(
                        "execSyscall: sys_clone: TID: addr=0x%llx, old=%lld, new=%lld",
                        child_tid,
                        *((uint64_t*)child_tid),
                        tid);
                    *((uint64_t*)child_tid) = tid;
                }
            }
            else
            {
                // Parent
                log("execSyscall: sys_clone: Parent!");
                ucontext->uc_mcontext->__ss.__rax = pid;
            }
        } break;

        case 0x3b: // sys_execve
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
            fflush(stdout);

            exit(255);
        } break;

        case 0x3d: // sys_wait4
        {
            int upid = ucontext->uc_mcontext->__ss.__rdi;
            int* stat_addr = (int*)(ucontext->uc_mcontext->__ss.__rsi);
            int options = ucontext->uc_mcontext->__ss.__rdx;
            void* rusage = (void*)ucontext->uc_mcontext->__ss.__r10;
//#ifdef DEBUG
            log("execSyscall: sys_wait4: upid=%d, stat_addr=%p, options=0x%x, rusage=%p",
                upid,
                stat_addr,
                options,
                rusage);
//#endif

            while (true)
            {
                sleep(1);
            }

/*
            int res = wait4(upid, stat_addr, options, NULL);
            int err = errno;
            log("execSyscall: sys_wait4: res=%d, err=%d", res, err);
            syscallErrnoResult(ucontext, res, res == 0, err);
*/
        } break;

        case 0x3f: // old uname
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
        } break;

        case 0x48: // sys_fcntl
        {
            unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
            unsigned int cmd = ucontext->uc_mcontext->__ss.__rsi;
            unsigned long arg = ucontext->uc_mcontext->__ss.__rdx;

#ifdef DEBUG
            log("execSyscall: sys_fcntl: fd=%d, cmd=0x%x, arg=0x%lx",
                fd,
                cmd,
                arg);
#endif

            uint8_t command = cmd & 0xf;

            if (command == F_SETOWN)
            {
                ucontext->uc_mcontext->__ss.__rax = 0;
            }
            else
            {
                int res = fcntl(fd, command, arg);
                int err = errno;
#ifdef DEBUG
                log("ElfProcess::execSyscall: sys_fcntl: res=%d, err=%d", res, err);
#endif
                syscallErrnoResult(ucontext, res, res != -1, err);
            }

        } break;

        case 0x4a: // sys_fsync
        {
            unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fsync: fd=%d\n", fd);
#endif
            int res = fsync(fd);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fsync: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;

        case 0x4d: // sys_ftruncate
        {
            unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
            unsigned long length = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_ftruncate: fd=%d, lendth=%ld\n", fd, length);
#endif
            int res = ftruncate(fd, length);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_ftruncate: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;

        case 0x4e: // sys_getdents
        {
            unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t direntPtr = ucontext->uc_mcontext->__ss.__rsi;
            unsigned int count = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_getdents: fd=%d, dirent=0x%llx, count=%d\n",
                fd,
                direntPtr,
                count);
#endif

            DIR* dirp;
            std::map<int, DIR*>::iterator it;
            it = m_dirs.find(fd);
            if (it != m_dirs.end())
            {
                dirp = it->second;
            }
            else
            {
                dirp = fdopendir(fd);
                m_dirs.insert(make_pair(fd, dirp));
            }
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_getdents:  -> dirp=%p\n", dirp);
#endif

            unsigned int offset = 0;
            while (true)
            {
                struct dirent* dirent = readdir(dirp);
                if (dirent == NULL)
                {
                    break;
                }

                struct linux_dirent* linux_dirent = (struct linux_dirent*)(direntPtr + offset);
                int namelen = strlen(dirent->d_name);
                //int entrylen = ALIGN(namelen + 1 + sizeof(linux_dirent) + 2, sizeof(long));
                int entrylen = sizeof(struct linux_dirent) + namelen + 1 + 1;
                if (offset + entrylen >= count)
                {
                    break;
                }

#if 0
                printf("ElfProcess::execSyscall: sys_getdents: %d: d_name=%s, entrylen=%d (%lu)\n", offset, dirent->d_name, entrylen, sizeof(struct linux_dirent));
#endif
                linux_dirent->d_ino = dirent->d_ino;
                linux_dirent->d_off = offset + entrylen;
                linux_dirent->d_reclen = entrylen;
                strncpy(linux_dirent->d_name, dirent->d_name, namelen);

                linux_dirent->d_name[namelen] = 0;
                linux_dirent->d_name[namelen + 1] = dirent->d_type;
                //hexdump((char*)linux_dirent, entrylen);
                offset += entrylen;
            }
            ucontext->uc_mcontext->__ss.__rax = (uint64_t)offset;
        } break;

        case 0x4f: // sys_getcwd
        {
            char* buf = (char*)(ucontext->uc_mcontext->__ss.__rdi);
            unsigned long size = ucontext->uc_mcontext->__ss.__rsi;
            char* res;
            res = getcwd(buf, size);
            ucontext->uc_mcontext->__ss.__rax = (uint64_t)res;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_getcwd: buf=%s\n", buf);
#endif
        } break;

        case 0x50: // sys_chdir
        {
            const char* filename = (char*)(ucontext->uc_mcontext->__ss.__rdi);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_chdir: filename=%s\n", filename);
#endif
            int res;
            res = m_fileSystem.chdir(filename);
            syscallErrnoResult(ucontext, res, res == 0, errno);
        } break;

        case 0x51: // sys_fchdir
        {
            int fd = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fchdir: fd=%d\n", fd);
#endif
            int res;
            res = fchdir(fd);
            syscallErrnoResult(ucontext, res, res == 0, errno);
        } break;

        case 0x52: // sys_rename
        {
            const char* oldname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
            const char* newname = (char*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_rename: oldname=%s, newname=%s\n", oldname, newname);
#endif
            int res = m_fileSystem.rename(oldname, newname);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_rename: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res == 0, errno);
        } break;

        case 0x53: // sys_mkdir
        {
            const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
            unsigned int mode = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_mkdir: pathname=%s, mode=0x%x\n", pathname, mode);
#endif

            int res;
            res = mkdir(pathname, mode);
            syscallErrnoResult(ucontext, res, res == 0, errno);
        } break;

        case 0x55: // sys_creat
        {
            const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
            unsigned int mode = ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_creat: pathname=%s, mode=0x%x\n", pathname, mode);
#endif

            int res = m_fileSystem.openat(AT_FDCWD, pathname, O_CREAT | O_TRUNC | O_WRONLY, mode);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_creat: res=%d, errno=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res >= 0, err);
 
        } break;

        case 0x57: // sys_unlink
        {
            const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_unlink: pathname=%s\n", pathname);
#endif
            int res = m_fileSystem.unlink(pathname);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_unlink: res=%d, errno=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res == 0, errno);

        } break;

        case 0x59: // sys_readlink
        {
            const char* path = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            char* buf = (char*)(ucontext->uc_mcontext->__ss.__rsi);
            size_t bufsize = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_readlink: path=%s (%p), buf=%p, bufsize=%lu\n", path, path, buf, bufsize);
#endif

            int res = -1;
            int err = 0;
            if (strcmp(path, "/proc/self/exe") == 0)
            {
                //strncpy(buf, m_line->getElfBinary()->getPath(), bufsize);
                strncpy(buf, "/bin/hello", bufsize);
                res = 0;
            }
            else
            {
                res = readlink(path, buf, bufsize);
                err = errno;
            }
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;

        case 0x5b: // sys_fchmod
        {
            int fd = ucontext->uc_mcontext->__ss.__rdi;
            int mode = ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fchmod: fd=%d, mode=%d\n", fd, mode);
#endif
            int res = fchmod(fd, mode);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fchmod: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;

        case 0x5f: // sys_umask
        {
            int mask = ucontext->uc_mcontext->__ss.__rdi;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_umask: mask=%d\n", mask);
#endif

            int res;
            res = umask(mask);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_umask: res=%d\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x61: // sys_getrlimit
        {
            unsigned int resource = ucontext->uc_mcontext->__ss.__rdi;
            struct rlimit* rlim = (struct rlimit*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            log("execSyscall: sys_getrlimit: resource=%d, rlim=%p", resource, rlim);
#endif

            if (resource <= 5)
            {
                int res = getrlimit(resource, rlim);
                int err = errno;
#ifdef DEBUG
                printf("ElfProcess::execSyscall: sys_getrlimit: res=%d, err=%d\n", res, err);
                printf("ElfProcess::execSyscall: sys_getrlimit:  -> cur=%lld, max=%lld\n", rlim->rlim_cur, rlim->rlim_max);
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
                exit(255);
            }
        } break;

        case 0x66: // sys_getuid
        {
            ucontext->uc_mcontext->__ss.__rax = getuid();
        } break;

        case 0x68: // sys_getgid
        {
            ucontext->uc_mcontext->__ss.__rax = getgid();
        } break;

        case 0x6b: // sys_geteuid
        {
            ucontext->uc_mcontext->__ss.__rax = geteuid();
        } break;

        case 0x6c: // sys_getegid
        {
            ucontext->uc_mcontext->__ss.__rax = getegid();
        } break;

        case 0x6d: // sys_setpgid
        {
            int pid = ucontext->uc_mcontext->__ss.__rdi;
            int pgid = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_setpgid: pid=%d, pgid=%d\n", pid, pgid);
#endif
            int res = setpgid(pid, pgid);
            int err = errno;
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;


        case 0x6e: // sys_getppid
        {
            ucontext->uc_mcontext->__ss.__rax = getppid();
        } break;

        case 0x6f: // sys_getpgrp
        {
            ucontext->uc_mcontext->__ss.__rax = getpgrp();
        } break;

        case 0x73: // sys_getgroups
        {
            int gidsetsize = ucontext->uc_mcontext->__ss.__rdi;
            gid_t* grouplist = (gid_t*)(ucontext->uc_mcontext->__ss.__rsi);
            int res = getgroups(gidsetsize, grouplist);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_getgroups: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res != -1, err);
        } break;

        case 0x82: // sys_rt_sigsuspend
        {
            void* unewset = (void*)(ucontext->uc_mcontext->__ss.__rdi);
            size_t sigsetsize = ucontext->uc_mcontext->__ss.__rsi;
            printf("ElfProcess::execSyscall: sys_rt_sigsuspend: unewset=%p, sigsetsize=%lu\n", unewset, sigsetsize);
            ucontext->uc_mcontext->__ss.__rax = -1;
            while(1)
            {
                sleep(1);
            }
        } break;

        case 0x95: // sys_mlock
        {
            void* addr = (void*)(ucontext->uc_mcontext->__ss.__rdi);
            unsigned long len = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_mlock: addr=%p, len=%ld\n", addr, len);
#endif
            int res;
            res = mlock(addr, len);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_mlock: res=%d, err=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res == 0, err);
        } break;

        case 0x9e: // sys_arch_prctl
        {
            int option = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t addr = (uint64_t)ucontext->uc_mcontext->__ss.__rsi;

            printf("ElfProcess::execSyscall: sys_arch_prctl: option=0x%x, addr=%llx\n", option, addr);
            printf("ElfProcess::execSyscall: sys_arch_prctl: Current: fs=0x%llx, gs=0x%llx\n", ucontext->uc_mcontext->__ss.__fs, ucontext->uc_mcontext->__ss.__gs);

            switch (option)
            {
                case ARCH_SET_GS:
                    ucontext->uc_mcontext->__ss.__gs = (uint64_t)addr;
                    ucontext->uc_mcontext->__ss.__rax = 0;
                    break;

                case ARCH_SET_FS:
                {
                    m_fs = (uint64_t)addr;
                    m_fsPtr = (uint64_t)addr;
                    printf("ElfProcess::execSyscall: sys_arch_prctl: ARCH_SET_FS=0x%llx\n", m_fs);
                    ucontext->uc_mcontext->__ss.__rax = 0;
                } break;

                case ARCH_GET_FS:
                    printf("ElfProcess::execSyscall: sys_arch_prctl: ARCH_GET_FS=0x%llx\n", m_fs);
                    ucontext->uc_mcontext->__ss.__rax = m_fs;
                    break;

                case ARCH_GET_GS:
                    ucontext->uc_mcontext->__ss.__rax = ucontext->uc_mcontext->__ss.__gs;
                    ucontext->uc_mcontext->__ss.__rax = 0;
                    break;
            }
        } break;

        case 0xa0: // sys_setrlimit
        {
            unsigned int resource = ucontext->uc_mcontext->__ss.__rdi;
            struct rlimit* rlim = (struct rlimit*)(ucontext->uc_mcontext->__ss.__rsi);
            log("execSyscall: sys_setrlimit: resource=%d, rlim->rlim_cur=%lld, rlim_max=%lld", resource, rlim->rlim_cur, rlim->rlim_max);

            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0xba: // sys_gettid
        {
             uint64_t tid;
             pthread_threadid_np(NULL, &tid);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_gettid: tid=%lld\n", tid);
#endif
            ucontext->uc_mcontext->__ss.__rax = tid;
        } break;

        case 0xbf: // sys_getxattr
        case 0xc0: // sys_lgetxattr
        {
            char* pathname = (char*)ucontext->uc_mcontext->__ss.__rdi;
            char* name = (char*)(ucontext->uc_mcontext->__ss.__rsi);
            void* value = (void*)(ucontext->uc_mcontext->__ss.__rdx);
            size_t size = ucontext->uc_mcontext->__ss.__r10;
            printf("ElfProcess::execSyscall: sys_getxattr: pathname=%s, name=%s, value=%p, size=%ld\n", pathname, name, value, size);
            if (!strcmp(name, "security.selinux"))
            {
                printf("ElfProcess::execSyscall: sys_getxattr:  -> No SELinux\n");
                ucontext->uc_mcontext->__ss.__rax = 0;
            }
            else if (!strcmp(name, "system.posix_acl_access") || !strcmp(name, "system.posix_acl_default"))
            {
                printf("ElfProcess::execSyscall: sys_getxattr:  -> No POSIX ACLs\n");
                ucontext->uc_mcontext->__ss.__rax = 0;
            }
            else
            {
                printf("ElfProcess::execSyscall: sys_getxattr:  -> Unrecognised attr: %s\n", name);
                exit(255);
            }
        } break;

        case 0xca: // sys_futex
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
        } break;

        case 0xda: // sys_set_tid_address
        {
#ifdef DEBUG
            int* tidptr = (int*)ucontext->uc_mcontext->__ss.__rdi;
            printf("ElfProcess::execSyscall: sys_set_tid_address: tidptr=%p\n", tidptr);
#endif
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0xdd: // sys_fadvise64
        {
#ifdef DEBUG
            int fd = ucontext->uc_mcontext->__ss.__rdi;
            size_t offset = ucontext->uc_mcontext->__ss.__rsi;
            size_t len = ucontext->uc_mcontext->__ss.__rdx;
            int advice = ucontext->uc_mcontext->__ss.__r10;

            printf("ElfProcess::execSyscall: sys_fadvise64: fd=%d, offset=%ld, len=%ld, advice=%d\n",
                fd,
                offset,
                len,
                advice);
#endif
            ucontext->uc_mcontext->__ss.__rax = 0;

        } break;

        case 0xe4: // sys_clock_gettime
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
                    exit(1);
            }

            int res;
            res = clock_gettime(clockid, tp);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_clock_gettime:  clockid=%d, res=%d\n", clockid, res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0xe7: // sys_exit_group
        {
            int errorCode = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_exit_group: errorCode=%d\n", errorCode);
#endif

            exit(errorCode);
        } break;

        case 0xea: // sys_tgkill
        {
            pid_t tgid = ucontext->uc_mcontext->__ss.__rdi;
            pid_t pid = ucontext->uc_mcontext->__ss.__rsi;
            int sig = ucontext->uc_mcontext->__ss.__rdx;

            printf("ElfProcess::execSyscall: sys_tgkill: tgid=%d, pid=%d, sig=%d\n", tgid, pid, sig);
            exit(1);
        } break;

        case 0x101: // sys_openat
        {
            uint64_t dfd = ucontext->uc_mcontext->__ss.__rdi;
            const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
            int flags = ucontext->uc_mcontext->__ss.__rdx;
            int mode = ucontext->uc_mcontext->__ss.__r10;
            int osx_flags = oflags2osx(flags);
#ifdef DEBUG
            printf(
                "ElfProcess::execSyscall: sys_openat: dfd=%lld, filename=%p, flags=0x%x (0x%x), mode=0x%x\n",
                dfd,
                filename,
                flags,
                osx_flags,
                mode);
#endif

            if (dfd == LINUX_AT_FDCWD)
            {
                dfd = AT_FDCWD; // Mac OS uses a different magic number
            }

            int res = m_fileSystem.openat(dfd, filename, osx_flags, mode);
            int err = errno;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_openat: res=%d, errno=%d\n", res, err);
#endif
            syscallErrnoResult(ucontext, res, res >= 0, err);
        } break;

        default:
            printf(
                "ElfProcess::execSyscall: ERROR: 0x%llx: Unhandled syscall: %llu (0x%llx)\n",
                ucontext->uc_mcontext->__ss.__rip,
                syscall,
                syscall);
            exit(1);
            break;
    }

    return true;
}

