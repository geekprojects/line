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

bool ElfProcess::execSyscall(uint64_t syscall, ucontext_t* ucontext)
{
    switch (syscall)
    {
        case 0x0: // sys_read
        {
            unsigned int fd = (ucontext->uc_mcontext->__ss.__rdi);
            const char* buf = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
            size_t count = ucontext->uc_mcontext->__ss.__rdx;
            int res = read(fd, (void*)buf, count);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_read: fd=%d, buf=%p, count=%lu: res=%d\n", fd, buf, count, res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x1: // write
        {
            unsigned int fd = (ucontext->uc_mcontext->__ss.__rdi);
            const char* buf = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
            size_t count = ucontext->uc_mcontext->__ss.__rdx;

            int res = write(fd, buf, count);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_write: fd=%d, buf=%p, count=%lu: res=%d\n", fd, buf, count, res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x2: // open
        {
            const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            int flags = ucontext->uc_mcontext->__ss.__rsi;
            int mode = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_open: filename=%s, flags=0x%x, mode=0x%x\n", filename, flags, mode);
#endif

            //if (!strncmp("/etc/", filename, 5) || !strncmp("/proc/", filename, 6))
            if (!strncmp("/proc/", filename, 6))
            {
                printf("ElfProcess::execSyscall: sys_open: System file: filename=%s\n", filename);
                exit(1);
            }

            int fd = open(filename, flags, mode);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_open: fd=%d\n", fd);
#endif

            ucontext->uc_mcontext->__ss.__rax = fd;
        } break;

        case 0x3: // sys_close
        {
            unsigned int fd = (ucontext->uc_mcontext->__ss.__rdi);
            if (fd != 0 && fd != 1)
            {
                int res = close(fd);
#ifdef DEBUG
                printf("ElfProcess::execSyscall: sys_close: fd=%u, res=%d\n", fd, res);
#endif
                ucontext->uc_mcontext->__ss.__rax = res;
            }
            else
            {
#ifdef DEBUG
                printf("ElfProcess::execSyscall: sys_close: fd=%u, STDOUT/IN\n", fd);
#endif
                ucontext->uc_mcontext->__ss.__rax = 0;
            }
        } break;

        case 0x4: // sys_stat
        {
            const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_stat: filename=%s, linux_stat=%p\n", filename, linux_stat);
#endif

            struct stat osx_stat;
            int res;
            res = stat(filename, &osx_stat);

            stat2linux(osx_stat, linux_stat);

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_stat: res=%d\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x5: // sys_fstat
        {
            uint64_t fd = ucontext->uc_mcontext->__ss.__rdi;
            linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fstat: fd=%lld, linux_stat=%p\n", fd, linux_stat);
#endif

            struct stat osx_stat;
            int res = fstat(fd, &osx_stat);

            stat2linux(osx_stat, linux_stat);

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fstat: res=%d\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
        } break;

        case 0x6: // sys_lstat
        {
            const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rsi);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_lstat: filename=%s, linux_stat=%p\n", filename, linux_stat);
#endif

            struct stat osx_stat;
            int res;
            res = lstat(filename, &osx_stat);

            stat2linux(osx_stat, linux_stat);

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_lstat: res=%d\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = res;
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
            printf(
                "ElfProcess::execSyscall: sys_mmap: addr=0x%llx, len=%llu, prot=0x%llx, flags=0x%llx->%x, fd=%lld, off=%lld\n",
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
            printf("ElfProcess::execSyscall: sys_mmap: -> result=%p, errno=%d\n", result, err);
#endif

            ucontext->uc_mcontext->__ss.__rax = (uint64_t)result;
        } break;

        case 0xa: // sys_mprotect
        {
            uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
            uint64_t prot = ucontext->uc_mcontext->__ss.__rdx & 7; // Only the RWX flags
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_mprotext: addr=0x%llx, len=%llu, prot=0x%llx\n", addr, len, prot);
#endif

            int res = mprotect((void*)addr, len, prot);
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_mprotext:  -> res=%d\n", res);
#endif

            ucontext->uc_mcontext->__ss.__rax = 0;
            //exit(0);
        } break;

        case 0xb: // sys_munmap
        {
            uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
            uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_munmap: addr=0x%llx, len=%llu\n", addr, len);
#endif

            int res = munmap((void*)addr, len);

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_munmap: -> res=%d\n", res);
#endif
            ucontext->uc_mcontext->__ss.__rax = (uint64_t)res;
        } break;

        case 0xc: // sys_brk
        {
            uint64_t brkarg = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_brk: brkarg=0x%llx\n", brkarg);
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
                printf("ElfProcess::execSyscall: sys_brk: newbrk=0x%llx, len=%llx\n", newbrk, len);
#endif
                void* maddr = mmap((void*)m_brk, len,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_FIXED | MAP_ANON | MAP_PRIVATE,
                    -1,
                    0);
#ifdef DEBUG
                printf("ElfProcess::execSyscall: sys_brk:  -> maddr=%p\n", maddr);
#endif
                //void* brkres = brk((const void*)brkarg);

                ucontext->uc_mcontext->__ss.__rax = (uint64_t)newbrk;
            }
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_brk: returning: 0x%llx\n", ucontext->uc_mcontext->__ss.__rax);
#endif

        } break;

        case 0xd: // sys_rt_sigaction
        {
            int sig = ucontext->uc_mcontext->__ss.__rdi;
            void* act = (void*)(ucontext->uc_mcontext->__ss.__rsi);
            void* oact = (void*)(ucontext->uc_mcontext->__ss.__rdx);
            size_t sigsetsize = ucontext->uc_mcontext->__ss.__r10;

            printf("ElfProcess::execSyscall: sys_rt_sigaction: sig=%d, act=%p, oact=%p, sigsetsize=%llu\n",
                sig,
                act,
                oact,
                sigsetsize);
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0xe: // sys_rt_sigprocmask
        {
            int how = ucontext->uc_mcontext->__ss.__rdi;
            void* nset = (void*)(ucontext->uc_mcontext->__ss.__rsi);
            void* oset = (void*)(ucontext->uc_mcontext->__ss.__rdx);
            size_t sigsetsize = ucontext->uc_mcontext->__ss.__r10;

            printf("ElfProcess::execSyscall: sys_rt_sigprocmask: how=%d, nset=%p, oset=%p, sigsetsize=%llu\n",
                how,
                nset,
                oset,
                sigsetsize);
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0x10: // sys_ioctl
        {
            unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
            unsigned int cmd = ucontext->uc_mcontext->__ss.__rsi;
            unsigned long arg = ucontext->uc_mcontext->__ss.__rdx;
            printf("ElfProcess::execSyscall: sys_ioctl: fd=%llx, cmd=0x%llx, arg=0x%llx\n", fd, cmd, arg);

            if (fd != 1)
            {
                printf("ElfProcess::execSyscall: sys_ioctl:  -> Only supported for fd 1\n");
                exit(1);
            }
            switch (cmd)
            {
                case TCGETS:
                {
                    struct termios* t = (struct termios*)arg;
                    printf("ElfProcess::execSyscall: sys_ioctl: TCGETS: iflag=0x%x, oflag=0x%x, cflag=0x%x, lflag=0x%x\n",
                        t->c_iflag,
                        t->c_oflag,
                        t->c_cflag,
                        t->c_lflag);
                    ucontext->uc_mcontext->__ss.__rax = 0;
                } break;

                case TIOCGWINSZ:
                {
                    printf("ElfProcess::execSyscall: sys_ioctl: TIOCGWINSZ\n");
                    struct winsize* ws = (struct winsize*)arg;
                    ws->ws_row = 25;
                    ws->ws_col = 80;
                    ucontext->uc_mcontext->__ss.__rax = 0;
                } break;

                default:
                    printf("ElfProcess::execSyscall: sys_ioctl: Unknown ioctl: 0x%llx\n", cmd);
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
            if (strcmp(path, "/etc/ld.so.nohwcap") == 0)
            {
                ucontext->uc_mcontext->__ss.__rax = -1;
            }
            else
            {
                printf("ElfProcess::execSyscall: sys_access: path=%s, mode=%d\n", path, mode);
                exit(1);
            }
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

        case 0x3f: // old uname
        {
            linux_oldutsname* utsname = (linux_oldutsname*)ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_utsname: utsname=%p\n", utsname);
#endif
            strcpy(utsname->sysname, "Linux");
            strcpy(utsname->nodename, "LinuxOnMac");
            strcpy(utsname->release, "4.4.24");
            strcpy(utsname->version, "4.4.24"); // The version I've been using as a reference
            strcpy(utsname->machine, "x86_64");
            ucontext->uc_mcontext->__ss.__rax = 0;
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

        case 0x59: // sys_readlink
        {
            const char* path = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
            char* buf = (char*)(ucontext->uc_mcontext->__ss.__rsi);
            size_t bufsize = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_readlink: path=%s (%p), buf=%p, bufsize=%lu\n", path, path, buf, bufsize);
#endif

            uint64_t res;
            if (strcmp(path, "/proc/self/exe") == 0)
            {
                //strncpy(buf, m_line->getElfBinary()->getPath(), bufsize);
                strncpy(buf, "/bin/hello", bufsize);
                res = 0;
            }
            else
            {
                res = readlink(path, buf, bufsize);
            }
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_readlink: result: %lld (%s)\n", res, buf);
#endif

            ucontext->uc_mcontext->__ss.__rax = res;
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

        case 0xba: // sys_gettid
        {
            mach_port_t port = mach_thread_self();
#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_gettid: tid=%d\n", port);
#endif
            ucontext->uc_mcontext->__ss.__rax = port;
        } break;

        case 0xca: // sys_futex
        {
            uint32_t* uaddr = (uint32_t*)ucontext->uc_mcontext->__ss.__rdi;
            int op = ucontext->uc_mcontext->__ss.__rsi;
            uint32_t val = ucontext->uc_mcontext->__ss.__rdx;
            void* utime = (void*)ucontext->uc_mcontext->__ss.__r10;
            uint32_t* uaddr2 = (uint32_t*)ucontext->uc_mcontext->__ss.__r8;
            uint32_t val3 = ucontext->uc_mcontext->__ss.__r9;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_futex: uaddr=%p, op=%d, val=%d\n", uaddr, op, val);
            printf("ElfProcess::execSyscall: sys_futex: uaddr value=0x%x\n", *uaddr);
#endif
            if (op != 129 || val != 1)
            {
                printf("ElfProcess::execSyscall: sys_futex: uaddr=%p, op=%d, val=%d\n", uaddr, op, val);
                printf("ElfProcess::execSyscall: sys_futex: uaddr value=0x%x\n", *uaddr);
                exit(1);
            }
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0xda: // sys_set_tid_address
        {
            int* tidptr = (int*)ucontext->uc_mcontext->__ss.__rdi;
            printf("ElfProcess::execSyscall: sys_set_tid_address: tidptr=%p\n", tidptr);
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0xdd: // sys_fadvise64
        {
            int fd = ucontext->uc_mcontext->__ss.__rdi;
            size_t offset = ucontext->uc_mcontext->__ss.__rsi;
            size_t len = ucontext->uc_mcontext->__ss.__rdx;
            int advice = ucontext->uc_mcontext->__ss.__r10;

#ifdef DEBUG
            printf("ElfProcess::execSyscall: sys_fadvise64: fd=%d, offset=%d, len=%d, advice=%d\n",
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

            clockid_t clockid;
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
            printf("ElfProcess::execSyscall: sys_exit_group: errorCode=%d\n", errorCode);
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
            printf(
                "ElfProcess::execSyscall: sys_openat: dfd=%lld, filename=%p, flags=0x%x, mode=0x%x\n",
                dfd,
                filename,
                flags,
                mode);
            hexdump(filename, 64);
            if (dfd == LINUX_AT_FDCWD)
            {
                dfd = AT_FDCWD; // Mac OS uses a different magic number
            }
            exit(1);
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

