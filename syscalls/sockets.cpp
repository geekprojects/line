
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "kernel.h"
#include "sockets.h"

using namespace std;

SYSCALL_METHOD(socket)
{
    int family = ucontext->uc_mcontext->__ss.__rdi;
    int type = ucontext->uc_mcontext->__ss.__rsi;
    int protocol = ucontext->uc_mcontext->__ss.__rdx;
    int osx_type = type & 0xf;
#ifdef DEBUG
    log(
        "sys_socket: family=0x%x, type=0x%x (0x%x), protocol=0x%x\n",
        family,
        type,
        osx_type,
        protocol);
#endif
    if (family != 1)
    {
        log("sys_socket: Unsupported family=0x%x\n", family);
        return false;
    }

    if (osx_type != 1)
    {
        log("sys_socket: Unsupported PF_UNIX type=0x%x\n", osx_type);
        return false;
    }

    if (protocol != 0)
    {
        log("sys_socket: Unsupported PF_UNIX protocol=0x%x\n", protocol);
        return false;
    }

    int res;
    res = socket(family, osx_type, protocol);
    int err = errno;
#ifdef DEBUG
    log("sys_socket: res=%d, err=%d\n", res, err);
#endif
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
    return true;
}

SYSCALL_METHOD(connect)
{
    int fd = ucontext->uc_mcontext->__ss.__rdi;
    void* addr = (void*)(ucontext->uc_mcontext->__ss.__rsi);
    int addrlen = ucontext->uc_mcontext->__ss.__rdx;

#ifdef DEBUG
    log(
        "sys_connect: fd=%d, addr=%p, addrlen=%d\n",
        fd,
        addr,
        addrlen);
#endif

    map<int, LinuxSocket*>::iterator it = m_sockets.find(fd);
    if (it != m_sockets.end())
    {
        LinuxSocket* socket = it->second;

        if (socket->family != PF_UNIX)
        {
            log(
                "sys_connect: Unexpected socket family: %d\n",
                socket->family);
            return false;
        }
        if (addrlen != sizeof(linux_sockaddr_un))
        {
            log(
                "sys_connect: Unexpected addrlen: %d\n",
                addrlen);
            return false;
        }
        linux_sockaddr_un* linux_sockaddr = (linux_sockaddr_un*)addr;
#ifdef DEBUG
        log("sys_connect: path: %s\n", linux_sockaddr->sun_path);
#endif

        sockaddr_un osx_sockaddr;
        osx_sockaddr.sun_len = addrlen;
        osx_sockaddr.sun_family = linux_sockaddr->sun_family;
        strncpy(osx_sockaddr.sun_path, linux_sockaddr->sun_path, 104);

        int res = connect(fd, (sockaddr*)&osx_sockaddr, sizeof(osx_sockaddr));
        int err = errno;
#ifdef DEBUG
        log("sys_connect: res=%d, err=%d\n", res, err);
#endif
        syscallErrnoResult(ucontext, res, res == 0, err);
    }
    else
    {
        log(
            "sys_connect: Unable to find socket for fd: %d\n",
            fd);
    }
    return true;
}

