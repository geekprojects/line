
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "kernel.h"
#include "fs.h"

using namespace std;

static void stat2linux(struct stat osx_stat, struct linux_stat* linux_stat)
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

SYSCALL_METHOD(stat)
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
#ifdef DEBUG
    log("execSyscall: sys_stat: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    free(osx_filename);

    return true;
}

SYSCALL_METHOD(fstat)
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
#ifdef DEBUG
    log("execSyscall: sys_stat: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(lstat)
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
#ifdef DEBUG
    log("execSyscall: sys_stat: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);
    return true;
}

SYSCALL_METHOD(access)
{
    const char* path = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
    int mode = (int)(ucontext->uc_mcontext->__ss.__rsi);

#ifdef DEBUG
    printf("ElfProcess::execSyscall: sys_access: path=%s, mode=0x%x\n", path, mode);
#endif
    int res = m_fileSystem.access(path, mode);
    int err = errno;
#ifdef DEBUG
    printf("ElfProcess::execSyscall: sys_access:  -> res=%d, errno=%d\n", res, errno);
#endif

    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(getdents)
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

    return true;
}

SYSCALL_METHOD(rename)
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
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(mkdir)
{
    const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    unsigned int mode = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
    printf("ElfProcess::execSyscall: sys_mkdir: pathname=%s, mode=0x%x\n", pathname, mode);
#endif

    int res = mkdir(pathname, mode);
    int err = errno;
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(unlink)
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
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(readlink)
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

    return true;
}

SYSCALL_METHOD(getxattr)
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
    return true;
}

