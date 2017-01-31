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

    char* path2linux(const char* path);
    char* path2osx(const char* path);
};

#endif
