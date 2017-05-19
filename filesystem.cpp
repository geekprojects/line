
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "filesystem.h"

//#define DEBUG

using namespace std;

struct FileSystemMount
{
    const char* path;
    const char* dest;
};

FileSystemMount g_fsMounts[] =
{
    {"/Users", "/Users"},
    {"/dev", "/dev"},
    {"/", "/Users/ian/projects/line/root"},
};

FileSystem::FileSystem() : Logger("FileSystem")
{
}

FileSystem::~FileSystem()
{
}

int FileSystem::openat(int dfd, const char* path, int oflags, int mode)
{
    char* osxPath = path2osx(path);
    if (osxPath == NULL)
    {
        errno = ENOENT;
        return -1;
    }

    int res = ::openat(dfd, osxPath, oflags, mode);
    int err = errno;
    free(osxPath);
    errno = err;

    return res;
}

int FileSystem::access(const char* path, int mode)
{
    char* osxPath = path2osx(path);
    if (osxPath == NULL)
    {
        errno = ENOENT;
        return -1;
    }

    int res = ::access(osxPath, mode);
    int err = errno;
    free(osxPath);
    errno = err;

    return res;
}

int FileSystem::chdir(const char* path)
{
    char* osxPath = path2osx(path);
    if (osxPath == NULL)
    {
        errno = ENOENT;
        return -1;
    }

    int res = ::chdir(osxPath);
    int err = errno;
    free(osxPath);
    errno = err;

    return res;
}

int FileSystem::link(const char* oldname, const char* newname)
{
    char* osxOldName = path2osx(oldname);
    if (osxOldName == NULL)
    {
        errno = ENOENT;
        return -1;
    }

    char* osxNewName = path2osx(newname);
    if (osxNewName == NULL)
    {
        free(osxOldName);
        errno = ENOENT;
        return -1;
    }

    int res = ::link(osxOldName, osxNewName);
    int err = errno;
    free(osxOldName);
    free(osxNewName);
    errno = err;

    return res;
}


int FileSystem::unlink(const char* path)
{
    char* osxPath = path2osx(path);
    if (osxPath == NULL)
    {
        errno = ENOENT;
        return -1;
    }

    int res = ::unlink(osxPath);
    int err = errno;
    free(osxPath);
    errno = err;

    return res;
}

int FileSystem::rename(const char* oldname, const char* newname)
{
    char* osxOldName = path2osx(oldname);
    if (osxOldName == NULL)
    {
        errno = ENOENT;
        return -1;
    }

    char* osxNewName = path2osx(newname);
    if (osxNewName == NULL)
    {
        free(osxOldName);
        errno = ENOENT;
        return -1;
    }

    int res = ::rename(osxOldName, osxNewName);
    int err = errno;
    free(osxOldName);
    free(osxNewName);
    errno = err;

    return res;
}

char* FileSystem::path2linux(const char* path)
{

    return NULL;
}

char* FileSystem::path2osx(const char* path)
{
    if (path == NULL)
    {
        return NULL;
    }
    log("path2osx: path=%s", path);
    string pathstr = string(path);

    if (!strncmp(path, "/dev/pts/", 9))
    {
        int id = atoi(path + 9);
        char* result = (char*)malloc(30);
        sprintf(result, "/dev/ttys%03d", id);
        log("path2osx: %s -> %s", path, result);
        return result;
    }

    if (pathstr.length() > 0 && pathstr[0] == '/')
    {
        int i;
        for (i = 0; i < (sizeof(g_fsMounts) / sizeof(FileSystemMount)); i++)
        {
#ifdef DEBUG
            log("path2osx: %d: %s -> %s",
                i,
                g_fsMounts[i].path,
                g_fsMounts[i].dest);
#endif

            int pathlen = strlen(g_fsMounts[i].path);

            if (!strncmp(path, g_fsMounts[i].path, pathlen))
            {
#ifdef DEBUG
                log("path2osx: -> Matched");
#endif
                string osx = string(g_fsMounts[i].dest) + "/" + pathstr.substr(pathlen);
#ifdef DEBUG
                log("path2osx: -> osx path=%s", osx.c_str());
#endif
                return strdup(osx.c_str());
            }
        }
    }
    else
    {
        char cwd[1024];
        getcwd(cwd, 1024);
        string newpath = string(cwd) + "/" + string(path);
        return path2osx(newpath.c_str());
    }

    return NULL;
}

#ifdef TEST
int main(int argc, char** argv)
{
    FileSystem fileSystem;

    char* result;
    result = fileSystem.path2osx("/usr/bin/base64");
    printf("%s\n", result);
    result = fileSystem.path2osx("README.md");
    printf("%s\n", result);

    return 0;
}
#endif

