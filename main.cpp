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
#include <signal.h>
#include <errno.h>

#include <getopt.h>

#include "line.h"
#include "filesystem.h"

static const struct option g_options[] =
{
    { "exec",    required_argument, NULL, 'e' },
    { "forked",  no_argument,       NULL, 'f' },
    { "trace",   no_argument,       NULL, 't' },
    { NULL,      0,                 NULL, 0 }
};

int main(int argc, char** argv)
{
    Line line;

const char* execopt = NULL;

    while (true)
    {
        int c = getopt_long(
            argc,
            argv,
            "+eft",
            g_options,
            NULL);

        if (c == -1)
        {
            break;
        }

        switch (c)
        {
            case 'e':
                execopt = optarg;
                break;

            case 'f':
            {
                line.setConfigForked(true);
                sigset_t set = 0;
                sigprocmask(SIG_SETMASK, &set, NULL);
            } break;

            case 't':
                line.setConfigTrace(true);
                break;

            default:
                exit(1);
                break;
        }
    }

    int remaining_argc = argc - optind;
    if (remaining_argc <= 0)
    {
        printf("%s <executable> <args ...>\n", argv[0]);
        exit(1);
    }

    const char* executable = argv[optind];
    if (execopt != NULL)
    {
        executable = execopt;
    }

    char* execargv[remaining_argc];
    int i;
    for (i = 0; i < remaining_argc; i++)
    {
        execargv[i] = strdup(argv[i + optind]);
    }

    // First see if we can find the executable in the Linux vfs
    FileSystem fs;
    char* linuxExec = fs.path2osx(executable);

int a = -1;
    if (linuxExec != NULL)
    {
        a = access(linuxExec, F_OK | X_OK);
    }

    if (linuxExec == NULL || a != 0)
    {
        // Nope, try the normal file system
        if (linuxExec != NULL)
        {
            free(linuxExec);
        }

        linuxExec = strdup(executable);
        a = access(linuxExec, F_OK | X_OK);
    }

    if (a != 0)
    {
        printf("%s: unable to find executable: %s -> %s\n", argv[0], executable, linuxExec);
        exit(1);
    }

    bool res;
    res = line.open(linuxExec);
    if (!res)
    {
        printf("%s: Unable to open %s\n", argv[0], argv[1]);
        return 1;
    }

    line.execute(remaining_argc, execargv);
    return 0;
}

