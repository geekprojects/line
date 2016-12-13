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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>

#include "line.h"
#include "elfprocess.h"
#include "utils.h"

#define X86_EFLAGS_T 0x100UL

static Line* g_line = NULL;

Line::Line()
{
    g_line = this;
    m_semaphore = NULL;
}

Line::~Line()
{
    if (m_semaphore != NULL)
    {
        sem_close(m_semaphore);
    }
}

bool Line::open(const char* elfpath)
{
    m_elfBinary.load(elfpath);

    m_semaphore = sem_open("line", O_CREAT, 0644);
    if (m_semaphore == SEM_FAILED)
    {
        printf("Line::open: Failed to create semaphore\n");
        return false;
    }

    return true;
}

bool Line::execute(int argc, char** argv)
{
    pid_t pid = fork();
    if (pid == 0)
    {
        ElfProcess* elfProcess = new ElfProcess(this, &m_elfBinary);

        bool res;
        res = m_elfBinary.map();
        if (!res)
        {
            exit(1);
        }

        res = m_elfBinary.loadLibraries();
        if (!res)
        {
            exit(1);
        }

        elfProcess->start(argc, argv);

        // Should never get here!
        exit(255);
    }

    m_elfPid = pid;

    sem_wait(m_semaphore);

    task_t  port;
    int res;
    res = task_for_pid(mach_task_self(), pid, &port);
    if (res != 0)
    {
        printf("Line::execute: Failed to get port for child\n");
        return false;
    }

    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    res = task_threads(port, &thread_list, &thread_count);
    if (res != 0)
    {
        printf("Line::execute: Failed to get threads for child\n");
        return false;
    }

    // Set the Trace flag on the child
    x86_thread_state_t gp_regs;
    unsigned int gp_count = x86_THREAD_STATE_COUNT;
    res = thread_get_state(thread_list[0], x86_THREAD_STATE, (thread_state_t) & gp_regs, &gp_count);
    if (res != 0)
    {
        int err = errno;
        printf("Line::execute: Failed to get thread state: res=%d, err=%d\n", res, err);
        exit(1);
    }

    // Set Single Step flags in eflags
    gp_regs.uts.ts64.__rflags = (gp_regs.uts.ts64.__rflags & ~X86_EFLAGS_T) | X86_EFLAGS_T;
    res = thread_set_state (thread_list[0], x86_THREAD_STATE,
                             (thread_state_t) &gp_regs, gp_count);

    // Restart the child
    res = task_resume(port);
    if (res != 0)
    {
        printf("Line::execute: Failed to resume child\n");
        return false;
    }

    int s;
    wait(&s);
    printf("Line::execute: Child exited with status %d\n", WEXITSTATUS(s));
    fflush(stdout);

    return true;
}

void Line::signal()
{
    sem_post(m_semaphore);
}

