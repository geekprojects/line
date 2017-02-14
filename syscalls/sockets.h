#ifndef __LINE_SYSCALLS_SOCKETS_H_
#define __LINE_SYSCALLS_SOCKETS_H_

struct linux_sockaddr_un
{
    uint16_t sun_family; /* AF_UNIX */
    char sun_path[108];   /* pathname */
};

#endif
