/*
 * line - Line Is Not an Emulator
 * Copyright (C) 2016 GeekProjects.com
 *
 * This file is part of line.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <unistd.h>

#include "line.h"
#include "filesystem.h"

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("%s <executable> <args ...>\n", argv[0]);
        exit(1);
    }

    char* execargv[argc - 1];
    int i;
    for (i = 0; i < argc - 1; i++)
    {
        execargv[i] = strdup(argv[i + 1]);
    }

    // First see if we can find the executable in the Linux vfs
    FileSystem fs;
    char* linuxExec = fs.path2osx(argv[1]);
    int a;
    a = access(linuxExec, F_OK | X_OK);
    if (a != 0)
    {
        // Nope, try the normal file system
        free(linuxExec);
        linuxExec = argv[1];
        a = access(linuxExec, F_OK | X_OK);
    }

    if (a != 0)
    {
        printf("%s: unable to find executable\n", argv[0]);
        exit(1);
    }

    Line line;
    bool res;
    res = line.open(linuxExec);
    if (!res)
    {
        printf("%s: Unable to open %s\n", argv[0], argv[1]);
        return 1;
    }

    line.execute(argc - 1, execargv);
    return 0;
}

