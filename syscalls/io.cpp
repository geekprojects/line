/*
 * This contains the syscalls related to file IO
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include "kernel.h"
#include "io.h"
#include "linux/term.h"

static int oflags2osx(int linux_flags)
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

SYSCALL_METHOD(openat)
{
    uint64_t dfd = ucontext->uc_mcontext->__ss.__rdi;
    const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
    int flags = ucontext->uc_mcontext->__ss.__rdx;
    int mode = ucontext->uc_mcontext->__ss.__r10;
    int osx_flags = oflags2osx(flags);

#ifdef DEBUG
    log(
        "sys_openat: dfd=%lld, filename=%s, flags=0x%x (0x%x), mode=0x%x",
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
    log("sys_openat: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res >= 0, err);

    return true;
}

SYSCALL_METHOD(creat)
{
    const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    unsigned int mode = ucontext->uc_mcontext->__ss.__rsi;

#ifdef DEBUG
    log("sys_creat: pathname=%s, mode=0x%x", pathname, mode);
#endif

    int res = m_fileSystem.openat(AT_FDCWD, pathname, O_CREAT | O_TRUNC | O_WRONLY, mode);
    int err = errno;
#ifdef DEBUG
    log("sys_creat: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res >= 0, err);

    return true;
}

SYSCALL_METHOD(read)
{
    unsigned int fd = (ucontext->uc_mcontext->__ss.__rdi);
    const char* buf = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
    size_t count = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
    //log("execSyscall: sys_read: fd=%d, buf=%p, count=%lu", fd, buf, count);
#endif
    int res = read(fd, (void*)buf, count);
    int err = errno;
    syscallErrnoResult(ucontext, res, res >= 0, err);

    return true;
}

SYSCALL_METHOD(write)
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

    return true;
}

SYSCALL_METHOD(writev)
{
    int fd = ucontext->uc_mcontext->__ss.__rdi;
    iovec* vec = (iovec*)(ucontext->uc_mcontext->__ss.__rsi);
    unsigned long vlen = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
    log("sys_writev: fd=%d, vec=%p (%p, %lu), vlen=%lu", fd, vec, vec->iov_base, vec->iov_len, vlen);
#endif

    ssize_t res = writev(fd, vec, vlen);
    int err = errno;
#ifdef DEBUG
    log("sys_writev: res=%lu", res);
#endif
    syscallErrnoResult(ucontext, res, res >= 0, err);
    return true;
}

SYSCALL_METHOD(open)
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

    return true;
}

SYSCALL_METHOD(close)
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

    return true;
}

SYSCALL_METHOD(lseek)
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
    return true;
}

SYSCALL_METHOD(ioctl)
{
    unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
    unsigned int request = ucontext->uc_mcontext->__ss.__rsi;
    unsigned long arg = ucontext->uc_mcontext->__ss.__rdx;

    int cmd = request & 0xffff;
#ifdef DEBUG
    log("execSyscall: sys_ioctl: fd=%d, cmd=0x%x, arg=0x%lx", fd, cmd, arg);
#endif

    switch (cmd)
    {
        case LINUX_TCGETS:
        {
#ifdef DEBUG
            struct termios* t = (struct termios*)arg;
            log("sys_ioctl: TCGETS: iflag=0x%x, oflag=0x%x, cflag=0x%x, lflag=0x%x",
                t->c_iflag,
                t->c_oflag,
                t->c_cflag,
                t->c_lflag);
#endif
            ucontext->uc_mcontext->__ss.__rax = 0;
       } break;

        case LINUX_TIOCGWINSZ:
        {
            int res = ioctl(fd, TIOCGWINSZ, &arg);
#ifdef DEBUG
            winsize* ws = (winsize*)arg;
            log("sys_ioctl: TIOCGWINSZ: ws_rows=%d, ws_cols=%d", ws->ws_row, ws->ws_col);
#endif
            int err = errno;
            syscallErrnoResult(ucontext, res, res >= 0, err);
        } break;

        case LINUX_TIOCSWINSZ:
        {
            int res;

            res = ioctl(fd, TIOCSWINSZ, &arg);
            int err = errno;
            syscallErrnoResult(ucontext, res, res >= 0, err);
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

        case LINUX_TCSETSW:
        {
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case LINUX_VT_GETMODE:
        {
            linux_vt_mode* vt_mode = (linux_vt_mode*)arg;
            vt_mode->mode = 0;
            vt_mode->waitv = 0;
            vt_mode->relsig = 0;
            vt_mode->acqsig = 0;
            vt_mode->frsig = 0;
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0x5431: // TIOCSPTLCK
        {
            ucontext->uc_mcontext->__ss.__rax = 0;
        } break;

        case 0x5430: // TIOCGPTN
        {
            log("sys_ioctl: TIOCGPTN: fd=%d", fd);

            char* pt = ptsname(fd);
            log("sys_ioctl: TIOCGPTN: pt=%s", pt);

            int id;
            sscanf(pt, "/dev/ttys%d", &id);

            log("sys_ioctl: TIOCGPTN: id=%d", id);

            ucontext->uc_mcontext->__ss.__rax = 0;

            int* idres = (int*)arg;
            *idres = id;
        } break;

        default:
            log("sys_ioctl: Unknown ioctl: 0x%x", cmd);
            exit(1);
            break;
    }
    return true;
}

SYSCALL_METHOD(pipe)
{
    int* filedes = (int*)(ucontext->uc_mcontext->__ss.__rdi);

#ifdef DEBUG
    log("sys_pipe: filedes=%p", filedes);
#endif
    int res = pipe(filedes);
    int err = errno;
#ifdef DEBUG
    log("sys_pipe: res=%d, errno=%d", res, err);
#endif

    syscallErrnoResult(ucontext, res, res != -1, err);
    return true;
}

SYSCALL_METHOD(select)
{
    int nfds = ucontext->uc_mcontext->__ss.__rdi;
    fd_set* readfds = (fd_set*)(ucontext->uc_mcontext->__ss.__rsi);
    fd_set* writefds = (fd_set*)(ucontext->uc_mcontext->__ss.__rdx);
    fd_set* errorfds = (fd_set*)(ucontext->uc_mcontext->__ss.__r10);
    struct timeval* timeout = (struct timeval*)(ucontext->uc_mcontext->__ss.__r8);

#ifdef DEBUG
    log("sys_select: nfds=%d, readfds=%p, writefds=%p, errorfds=%p, timeout=%p",
        nfds,
        readfds,
        writefds,
        errorfds,
        timeout);
#endif
    int res = select(nfds, readfds, writefds, errorfds, timeout);
    int err = errno;
#ifdef DEBUG
    log("sys_select: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res != -1, err);
    return true;
}

SYSCALL_METHOD(dup)
{
    int filedes = ucontext->uc_mcontext->__ss.__rdi;

#ifdef DEBUG
    log("sys_dup: fd=%d", filedes);
#endif

    int res = dup(filedes);
    int err = errno;

#ifdef DEBUG
    log("sys_dup: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res != -1, err);
    return true;
}

SYSCALL_METHOD(dup2)
{
    int newfd = ucontext->uc_mcontext->__ss.__rsi;
    int filedes = ucontext->uc_mcontext->__ss.__rdi;

#ifdef DEBUG
    log("sys_dup2: fd=%d, newfd=%d", filedes, newfd);
#endif

    int res = dup2(filedes, newfd);
    int err = errno;

#ifdef DEBUG
    log("sys_dup2: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res != -1, err);
    return true;
}

SYSCALL_METHOD(fcntl)
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
        log("sys_fcntl: res=%d, err=%d", res, err);
#endif
        syscallErrnoResult(ucontext, res, res != -1, err);
    }
    return true;
}

SYSCALL_METHOD(fsync)
{
    unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
#ifdef DEBUG
    log("sys_fsync: fd=%d", fd);
#endif
    int res = fsync(fd);
    int err = errno;
#ifdef DEBUG
    log("sys_fsync: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);
    return true;
}

SYSCALL_METHOD(ftruncate)
{
    unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
    unsigned long length = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
    log("sys_ftruncate: fd=%d, lendth=%ld", fd, length);
#endif
    int res = ftruncate(fd, length);
    int err = errno;
#ifdef DEBUG
    log("sys_ftruncate: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(fadvise64)
{
#ifdef DEBUG
    int fd = ucontext->uc_mcontext->__ss.__rdi;
    size_t offset = ucontext->uc_mcontext->__ss.__rsi;
    size_t len = ucontext->uc_mcontext->__ss.__rdx;
    int advice = ucontext->uc_mcontext->__ss.__r10;

    log("sys_fadvise64: fd=%d, offset=%ld, len=%ld, advice=%d",
        fd,
        offset,
        len,
        advice);
#endif
    ucontext->uc_mcontext->__ss.__rax = 0;

    return true;
}

