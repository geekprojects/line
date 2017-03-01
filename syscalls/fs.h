#ifndef __LINE_SYSCALLS_FS_H_
#define __LINE_SYSCALLS_FS_H_

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

typedef struct {
        int     val[2];
} __kernel_fsid_t;

struct linux_statfs {
        long f_type;
        long f_bsize;
        long f_blocks;
        long f_bfree;
        long f_bavail;
        long f_files;
        long f_ffree;
        __kernel_fsid_t f_fsid;
        long f_namelen;
        long f_frsize;
        long f_flags;
        long f_spare[4];
};


#endif
