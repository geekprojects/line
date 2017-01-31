#ifndef __LINE_LINUX_SYSCALL_H_
#define __LINE_LINUX_SYSCALL_H_

#define LINUX_EAGAIN 11

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

#define LINUX_MAP_SHARED      0x01            /* Share changes */
#define LINUX_MAP_PRIVATE     0x02            /* Changes are private */
#define LINUX_MAP_TYPE        0x0f            /* Mask for type of mapping */
#define LINUX_MAP_FIXED       0x10            /* Interpret addr exactly */
#define LINUX_MAP_ANONYMOUS   0x20            /* don't use a file */
#define LINUX_MAP_NORESERVE   0x4000          /* don't check for reservations */

struct linux_iovec
{
    void *iov_base;     /* Pointer to data.  */
    size_t iov_len;     /* Length of data.  */
};

#define LINUX_OLD_UTSNAME_LENGTH 65
struct  linux_oldutsname
{
    char sysname[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Name of OS */
    char nodename[LINUX_OLD_UTSNAME_LENGTH]; /* [XSI] Name of this network node */
    char release[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Release level */
    char version[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Version level */
    char machine[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Hardware type */
};

struct linux_stat
  {
    uint64_t st_dev;
//uint32_t __pad0;
uint32_t __pad1;
    uint64_t st_ino;
    unsigned int st_nlink;
    unsigned int st_mode;
    unsigned int st_uid;
    unsigned int st_gid;
    //unsigned int __pad2;
    uint64_t st_rdev;
    uint32_t __pad2;
    uint64_t st_size;
    unsigned long int st_blksize;
    unsigned long int st_blocks;

    long st_atime_;
    unsigned long st_atime_nsec;
    long st_ctime_;
    unsigned long st_ctime_nsec;
    long st_mtime_;
    unsigned long st_mtime_nsec;

    unsigned long int __glibc_reserved4;
#define _HAVE___UNUSED4
    unsigned long int __glibc_reserved5;
#define _HAVE___UNUSED5
} __attribute__((__packed__));

#define LINUX_AT_FDCWD -100

#define LINUX_CLOCK_REALTIME                  0
#define LINUX_CLOCK_MONOTONIC                 1
#define LINUX_CLOCK_PROCESS_CPUTIME_ID        2
#define LINUX_CLOCK_THREAD_CPUTIME_ID         3
#define LINUX_CLOCK_MONOTONIC_RAW             4
#define LINUX_CLOCK_REALTIME_COARSE           5
#define LINUX_CLOCK_MONOTONIC_COARSE          6
#define LINUX_CLOCK_BOOTTIME                  7
#define LINUX_CLOCK_REALTIME_ALARM            8
#define LINUX_CLOCK_BOOTTIME_ALARM            9
#define LINUX_CLOCK_SGI_CYCLE                 10      /* Hardware specific */
#define LINUX_CLOCK_TAI                       11

struct linux_sockaddr_un {
        uint16_t sun_family; /* AF_UNIX */
        char sun_path[108];   /* pathname */
};

#define LINUX_DT_UNKNOWN      0
#define LINUX_DT_FIFO         1
#define LINUX_DT_CHR          2
#define LINUX_DT_DIR          4
#define LINUX_DT_BLK          6
#define LINUX_DT_REG          8
#define LINUX_DT_LNK          10
#define LINUX_DT_SOCK         12
#define LINUX_DT_WHT          14

struct linux_dirent
{
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[0];  /* Filename (null-terminated) */
                        /* length is actually (d_reclen - 2 -
                           offsetof(struct linux_dirent, d_name) */
/*
    char           d_type;    // File type (only since Linux 2.6.4;
                              // offset is (d_reclen - 1))
*/
} __attribute__((__packed__));

#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE    0x00002000      /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK     0x00004000      /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT    0x00008000      /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD    0x00010000      /* Same thread group? */
#define CLONE_NEWNS     0x00020000      /* New mount namespace group */
#define CLONE_SYSVSEM   0x00040000      /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS    0x00080000      /* create a new TLS for the child */
#define CLONE_PARENT_SETTID     0x00100000      /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID    0x00200000      /* clear the TID in the child */
#define CLONE_DETACHED          0x00400000      /* Unused, ignored */
#define CLONE_UNTRACED          0x00800000      /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID      0x01000000      /* set the TID in the child */
/* 0x02000000 was previously the unused CLONE_STOPPED (Start in stopped state)
   and is now available for re-use. */
#define CLONE_NEWUTS            0x04000000      /* New utsname namespace */
#define CLONE_NEWIPC            0x08000000      /* New ipc namespace */
#define CLONE_NEWUSER           0x10000000      /* New user namespace */
#define CLONE_NEWPID            0x20000000      /* New pid namespace */
#define CLONE_NEWNET            0x40000000      /* New network namespace */
#define CLONE_IO                0x80000000      /* Clone io context */

#define FUTEX_WAIT              0
#define FUTEX_WAKE              1
#define FUTEX_FD                2
#define FUTEX_REQUEUE           3
#define FUTEX_CMP_REQUEUE       4
#define FUTEX_WAKE_OP           5
#define FUTEX_LOCK_PI           6
#define FUTEX_UNLOCK_PI         7
#define FUTEX_TRYLOCK_PI        8
#define FUTEX_WAIT_BITSET       9
#define FUTEX_WAKE_BITSET       10
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12

#define FUTEX_PRIVATE_FLAG      128
#define FUTEX_CLOCK_REALTIME    256
#define FUTEX_CMD_MASK          ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

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

#endif
