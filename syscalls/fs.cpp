
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>

#include "kernel.h"
#include "fs.h"
#include "io.h"

using namespace std;

static uint64_t dev_makedev(uint32_t __major, uint32_t __minor)
{
  return ((__minor & 0xff) | ((__major & 0xfff) << 8)
          | (((uint64_t) (__minor & ~0xff)) << 12)
          | (((uint64_t) (__major & ~0xfff)) << 32));
}

static void stat2linux(struct stat osx_stat, struct linux_stat* linux_stat)
{
    memset(linux_stat, 0, sizeof(struct linux_stat));

    int dev_major = (osx_stat.st_dev >> 24) & 0xff;
    int dev_minor = (osx_stat.st_dev & 0xffffff);
    linux_stat->st_dev = dev_makedev(dev_major, dev_minor);

    //linux_stat->st_dev = osx_stat.st_dev;         /* Device.  */
    linux_stat->st_ino = osx_stat.st_ino;         /* File serial number.  */
    linux_stat->st_mode = osx_stat.st_mode;        /* File mode.  */
    linux_stat->st_nlink = osx_stat.st_nlink;       /* Link count.  */
    linux_stat->st_uid = osx_stat.st_uid;         /* User ID of the file's owner.  */
    linux_stat->st_gid = osx_stat.st_gid;         /* Group ID of the file's group. */

    int rdev_major = (osx_stat.st_rdev >> 24) & 0xff;
    int rdev_minor = (osx_stat.st_rdev & 0xffffff);
    if (rdev_major == 16)
    {
        rdev_major = 3;
    }
    linux_stat->st_rdev = dev_makedev(rdev_major, rdev_minor);

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

SYSCALL_METHOD(newfstatat)
{
    uint64_t fd = ucontext->uc_mcontext->__ss.__rdi;
    const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rsi);
    linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rdx);

    char* osx_filename = m_fileSystem.path2osx(filename);

if (fd == LINUX_AT_FDCWD)
{
fd = AT_FDCWD;
}

#ifdef DEBUG
    log("execSyscall: sys_newfstatat: fd=%lld, filename=%s (%s), linux_stat=%p", fd, filename, osx_filename, linux_stat);
#endif

    struct stat osx_stat;
int res = fstatat(fd, osx_filename, &osx_stat, 0);
int err = errno;

    if (res == 0)
    {
        stat2linux(osx_stat, linux_stat);
    }
#ifdef DEBUG
    log("execSyscall: sys_newfstatat: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(lstat)
{
    const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
    linux_stat* linux_stat = (struct linux_stat*)(ucontext->uc_mcontext->__ss.__rsi);

    char* osx_filename = m_fileSystem.path2osx(filename);
#ifdef DEBUG
    log("execSyscall: sys_lstat: filename=%s (%s), linux_stat=%p", filename, osx_filename, linux_stat);
#endif


    struct stat osx_stat;
    int res;
    res = lstat(osx_filename, &osx_stat);
    int err = errno;

    free(osx_filename);

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

    char* osx_path = m_fileSystem.path2osx(path);

#ifdef DEBUG
    log("sys_access: path=%s (%s), mode=0x%x", path, osx_path, mode);
#endif
    int res = m_fileSystem.access(osx_path, mode);
    int err = errno;
#ifdef DEBUG
    log("sys_access:  -> res=%d, errno=%d", res, errno);
#endif

    free(osx_path);

    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(getdents)
{
    unsigned int fd = ucontext->uc_mcontext->__ss.__rdi;
    uint64_t direntPtr = ucontext->uc_mcontext->__ss.__rsi;
    unsigned int count = ucontext->uc_mcontext->__ss.__rdx;
#ifdef DEBUG
    log("sys_getdents: fd=%d, dirent=0x%llx, count=%d",
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
    log("sys_getdents:  -> dirp=%p", dirp);
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
        log("sys_getdents: %d: d_name=%s, entrylen=%d (%lu)", offset, dirent->d_name, entrylen, sizeof(struct linux_dirent));
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
    log("sys_rename: oldname=%s, newname=%s", oldname, newname);
#endif
    int res = m_fileSystem.rename(oldname, newname);
    int err = errno;
#ifdef DEBUG
    log("sys_rename: res=%d, err=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(mkdir)
{
    const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    unsigned int mode = ucontext->uc_mcontext->__ss.__rsi;
#ifdef DEBUG
    log("sys_mkdir: pathname=%s, mode=0x%x", pathname, mode);
#endif

    char* osxPathName = m_fileSystem.path2osx(pathname);
    if (osxPathName == NULL)
    {
        return false;
    }

    int res = mkdir(osxPathName, mode);


    int err = errno;
    syscallErrnoResult(ucontext, res, res == 0, err);

free(osxPathName);

    return true;
}

SYSCALL_METHOD(rmdir)
{
    const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
#ifdef DEBUG
    log("sys_rmdir: pathname=%s", pathname);
#endif

    char* osxPathName = m_fileSystem.path2osx(pathname);
    if (osxPathName == NULL)
    {
        return false;
    }

    int res = rmdir(osxPathName);
    int err = errno;
    syscallErrnoResult(ucontext, res, res == 0, err);

#ifdef DEBUG
    log("sys_rmdir: res=%d, errno=%d", res, err);
#endif

    free(osxPathName);

    return true;
}

SYSCALL_METHOD(link)
{
    const char* oldname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
    const char* newname = (char*)(ucontext->uc_mcontext->__ss.__rsi);

log("sys_link: oldname=%s, newname=%s", oldname, newname);
int res = m_fileSystem.link(oldname, newname);
int err = errno;
log("sys_link: res=%d, err=%d", res, err);
    syscallErrnoResult(ucontext, res, res == 0, err);

return true;
}

SYSCALL_METHOD(unlink)
{
    const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rdi);
#ifdef DEBUG
    log("sys_unlink: pathname=%s", pathname);
#endif
    int res = m_fileSystem.unlink(pathname);
    int err = errno;
#ifdef DEBUG
    log("sys_unlink: res=%d, errno=%d", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(unlinkat)
{
    int fd = ucontext->uc_mcontext->__ss.__rdi;
    const char* pathname = (char*)(ucontext->uc_mcontext->__ss.__rsi);

if (fd == LINUX_AT_FDCWD)
{
fd = AT_FDCWD;
}

    char* osx_filename = m_fileSystem.path2osx(pathname);

#ifdef DEBUG
    log("sys_unlinkat: pathname=%s (%s)", pathname, osx_filename);
#endif

    int res = unlinkat(fd, osx_filename, AT_REMOVEDIR);
    int err = errno;

#ifdef DEBUG
    log("sys_unlink: res=%d, errno=%d", res, err);
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
    log("sys_readlink: path=%s (%p), buf=%p, bufsize=%lu", path, path, buf, bufsize);
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
    log("sys_getxattr: pathname=%s, name=%s, value=%p, size=%ld", pathname, name, value, size);
    if (!strcmp(name, "security.selinux"))
    {
        log("sys_getxattr:  -> No SELinux");
        ucontext->uc_mcontext->__ss.__rax = 0;
    }
    else if (!strcmp(name, "system.posix_acl_access") || !strcmp(name, "system.posix_acl_default"))
    {
        log("sys_getxattr:  -> No POSIX ACLs");
        ucontext->uc_mcontext->__ss.__rax = 0;
    }
    else
    {
        log("sys_getxattr:  -> Unrecognised attr: %s", name);
        exit(255);
    }
    return true;
}

SYSCALL_METHOD(statfs)
{
    char* pathname = (char*)ucontext->uc_mcontext->__ss.__rdi;
    struct linux_statfs* linux_statfs = (struct linux_statfs*)(ucontext->uc_mcontext->__ss.__rsi);

#ifdef DEBUG
    log("sys_statfs: pathname=%s, linux_statfs=%p", pathname, linux_statfs);
#endif

    if (!strncmp("/dev/pts", pathname, 8))
    {
        // Pretend to have a /dev/pts mount!
        memset(linux_statfs, 0, sizeof(struct linux_statfs));
        linux_statfs->f_type = DEVPTS_SUPER_MAGIC;
        linux_statfs->f_bsize = 1024;
        linux_statfs->f_blocks = 0;
        linux_statfs->f_bfree = 0;
        linux_statfs->f_bavail = 0;
        linux_statfs->f_files = 0;
        linux_statfs->f_ffree = 0;

        ucontext->uc_mcontext->__ss.__rax = 0;
 
        return true;
    }
    else if (!strncmp("/dev", pathname, 4))
    {
        // Fake the /dev mount!
        memset(linux_statfs, 0, sizeof(struct linux_statfs));
        linux_statfs->f_type = DEVFS_SUPER_MAGIC;
        linux_statfs->f_bsize = 1024;
        linux_statfs->f_blocks = 0;
        linux_statfs->f_bfree = 0;
        linux_statfs->f_bavail = 0;
        linux_statfs->f_files = 0;
        linux_statfs->f_ffree = 0;

        ucontext->uc_mcontext->__ss.__rax = 0;
 
        return true;
    }

    char* osxPathName = m_fileSystem.path2osx(pathname);
    if (osxPathName == NULL)
    {
        errno = ENOENT;
        return false;
    }

#ifdef DEBUG
    log("sys_statfs: osxOldName=%s", osxPathName);
#endif

    struct statfs osx_statfs;
    int res = statfs(osxPathName, &osx_statfs);
    int err = errno;
    log("sys_statfs: res=%d, err=%d", res, err);

    if (res == 0)
    {
        memset(linux_statfs, 0, sizeof(struct linux_statfs));
        linux_statfs->f_type = 0;
        linux_statfs->f_bsize = osx_statfs.f_bsize;
        linux_statfs->f_blocks = osx_statfs.f_blocks;
        linux_statfs->f_bfree = osx_statfs.f_bfree;
        linux_statfs->f_bavail = osx_statfs.f_bavail;
        linux_statfs->f_files = osx_statfs.f_files;
        linux_statfs->f_ffree = osx_statfs.f_ffree;
        //linux_statfs->f_namelen = osx_statfs->f_namelen;
    }

    syscallErrnoResult(ucontext, res, res == 0, err);

    return true;
}

SYSCALL_METHOD(utimes)
{
    char* pathname = (char*)ucontext->uc_mcontext->__ss.__rdi;
    struct timeval* times = (struct timeval*)(ucontext->uc_mcontext->__ss.__rsi);

char* osxpath = m_fileSystem.path2osx(pathname);

log("sys_utimes: pathname=%s->%s, times=%p\n", pathname, osxpath, times);

int res;
res = utimes(osxpath, times);
int err = errno;
log("sys_utimes: res=%d, err=%d\n", res, err);

    syscallErrnoResult(ucontext, res, res == 0, err);

free(osxpath);

    return true;
}

SYSCALL_METHOD(chown)
{
    const char* path = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
    char* osxpath = m_fileSystem.path2osx(path);
    int uid = ucontext->uc_mcontext->__ss.__rsi;
    int gid = ucontext->uc_mcontext->__ss.__rdx;

#ifdef DEBUG
    log("sys_chown: path=%p->%p, uid=%d, gid=%d\n", path, osxpath, uid, gid);
#endif

    uid_t thisuid = getuid();
    uid_t thisgid = getgid();
    log("sys_chown:  this uid=%d, gid=%d", thisuid, thisgid);
    if (uid == thisuid && gid == thisgid)
    {
        int res;
        res = chown(osxpath, uid, thisgid);
        int err = errno;
        log("sys_chown: res=%d, err=%d\n", res, err);
        syscallErrnoResult(ucontext, res, res == 0, err);
    }
    else
    {
        log("sys_chown: Not chowning to other user!");
        ucontext->uc_mcontext->__ss.__rax = 0;
    }

    free(osxpath);
    return true;

/*
    int res = chmod(osxpath, mode);
    int err = errno;
#ifdef DEBUG
    log("sys_chmod: res=%d, err=%d\n", res, err);
#endif
    syscallErrnoResult(ucontext, res, res == 0, err);

    free(osxpath);

    return true;
*/
}


