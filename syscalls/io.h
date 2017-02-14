#ifndef __LINE_SYSCALLS_IO_H_
#define __LINE_SYSCALLS_IO_H_

#define LINUX_AT_FDCWD -100

#define LINUX_O_ACCMODE       00000003
#define LINUX_O_RDONLY        00000000
#define LINUX_O_WRONLY        00000001
#define LINUX_O_RDWR          00000002
#define LINUX_O_CREAT         00000100        /* not fcntl */
#define LINUX_O_EXCL          00000200        /* not fcntl */
#define LINUX_O_NOCTTY        00000400        /* not fcntl */
#define LINUX_O_TRUNC         00001000        /* not fcntl */
#define LINUX_O_APPEND        00002000
#define LINUX_O_NONBLOCK      00004000
#define LINUX_O_DSYNC         00010000        /* used to be O_SYNC, see below */
#define LINUX_FASYNC          00020000        /* fcntl, for BSD compatibility */
#define LINUX_O_DIRECT        00040000        /* direct disk access hint */
#define LINUX_O_LARGEFILE     00100000
#define LINUX_O_DIRECTORY     00200000        /* must be a directory */

// read/writev structure
struct linux_iovec
{
    void *iov_base;     /* Pointer to data.  */
    size_t iov_len;     /* Length of data.  */
};

#endif
