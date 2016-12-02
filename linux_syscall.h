#ifndef __LINE_LINUX_SYSCALL_H_
#define __LINE_LINUX_SYSCALL_H_

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
    unsigned long   st_dev;         /* Device.  */
    unsigned long   st_ino;         /* File serial number.  */
    unsigned int    st_mode;        /* File mode.  */
    unsigned int    st_nlink;       /* Link count.  */
    unsigned int    st_uid;         /* User ID of the file's owner.  */
    unsigned int    st_gid;         /* Group ID of the file's group. */
    unsigned long   st_rdev;        /* Device number, if device.  */
    unsigned long   __pad1;
    long            st_size;        /* Size of file, in bytes.  */
    int             st_blksize;     /* Optimal block size for I/O.  */
    int             __pad2;
    long            st_blocks;      /* Number 512-byte blocks allocated. */
    long            st_atime_;       /* Time of last access.  */
    unsigned long   st_atime_nsec;
    long            st_mtime_;       /* Time of last modification.  */
    unsigned long   st_mtime_nsec;
    long            st_ctime_;       /* Time of last status change.  */
    unsigned long   st_ctime_nsec;
    unsigned int    __unused4;
    unsigned int    __unused5;
};

#endif
