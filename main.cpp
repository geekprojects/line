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
#include <sys/mman.h>
#include <mach/vm_map.h>
#include <mach/mach_init.h>
#include <malloc/malloc.h>

#include <getopt.h>

#include "line.h"
#include "filesystem.h"

__asm__(".zerofill LINE_EXEC, LINE_EXEC");
char __line_exec[0xf000000] __attribute__((section("LINE_EXEC, LINE_EXEC")));

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
/*
    void* ptr = malloc(16);
    printf("line: ptr=%p\n", ptr);

    malloc_zone_print(NULL, true);

    printf("Unmapping reserved regions...\n");
    munmap((void*)0x800000, 0x800000);
    printf("Done!\n");
    fflush(stdout);
*/
/*
int vmres = vm_deallocate(mach_task_self(), 0x0, 0x100000000);
printf("vmres=%d\n", vmres);
*/

/*
int mres = munmap((void*)0x1000, 0x100000000 - 0x1000);
printf("munmap res=%d\n", mres);
*/

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

    bool res;
    res = line.open(executable);
    if (!res)
    {
        printf("%s: Unable to open %s\n", argv[0], executable);
        return 1;
    }

    line.execute(remaining_argc, execargv);
    return 0;
}

