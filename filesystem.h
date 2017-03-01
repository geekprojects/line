#ifndef __LINE_FILESYSTEM_H_
#define __LINE_FILESYSTEM_H_

#include <string>

class FileSystem
{
 private:

 public:
    FileSystem();
    ~FileSystem();

    int openat(int fd, const char* path, int oflags, int mode = 0);

    int access(const char* path, int mode);
    int chdir(const char* path);
    int link(const char* oldname, const char* newname);
    int unlink(const char* path);
    int rename(const char* oldname, const char* newname);

    char* path2linux(const char* path);
    char* path2osx(const char* path);
};

#endif
