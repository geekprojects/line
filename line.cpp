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
#include "process.h"
#include "utils.h"

#define X86_EFLAGS_T 0x100UL

static Line* g_line = NULL;

Line::Line()
{
    g_line = this;

    pthread_cond_init(&m_cond, NULL);
    pthread_mutex_init(&m_condMutex, NULL);
    pthread_cond_init(&m_singleStepCond, NULL);
    pthread_mutex_init(&m_singleStepCondMutex, NULL);
}

Line::~Line()
{
    pthread_cond_destroy(&m_cond);
    pthread_mutex_destroy(&m_condMutex);
    pthread_cond_destroy(&m_singleStepCond);
    pthread_mutex_destroy(&m_singleStepCondMutex);
}

bool Line::open(const char* elfpath)
{
    bool res;

    res = m_elfBinary.load(elfpath);
    if (!res)
    {
        return false;
    }

    return true;
}

struct elfthreaddata
{
    Line* line;
    int argc;
    char** argv;
};

static void* elfentry(void* args)
{
    elfthreaddata* data = (elfthreaddata*)args;
    data->line->elfMain(data->argc, data->argv);
    return NULL;
}

bool Line::execute(int argc, char** argv)
{
    elfthreaddata* data = new elfthreaddata();
    data->line = this;
    data->argc = argc;
    data->argv = argv;

    // Create ELF Thread
    pthread_create(&m_elfThread, NULL, elfentry, data);

    // Get ELF Thread port
    task_t port = pthread_mach_thread_np(m_elfThread);

    // Wait for ELF Thread to be ready
    pthread_cond_wait(&m_cond, &m_condMutex);

    int res;

#ifdef DEBUG
    printf("Line::execute: Setting single step...\n");
#endif

    /*
     * Set the Trace flag on the child
     */

    // Get current state
    x86_thread_state_t gp_regs;
    unsigned int gp_count = x86_THREAD_STATE_COUNT;
    res = thread_get_state(port, x86_THREAD_STATE, (thread_state_t)&gp_regs, &gp_count);
    if (res != 0)
    {
        int err = errno;
        printf("Line::execute: Failed to get thread state: res=%d, err=%d\n", res, err);
        exit(1);
    }

    // Set Single Step flags in eflags
    gp_regs.uts.ts64.__rflags = (gp_regs.uts.ts64.__rflags & ~X86_EFLAGS_T) | X86_EFLAGS_T;
    res = thread_set_state(
        port,
        x86_THREAD_STATE,
        (thread_state_t) &gp_regs,
        gp_count);

    // Wake the ELF Thread (In to Single Step mode)
    pthread_cond_signal(&m_singleStepCond);

    // Wait for the ELF thread to complete
    void* value;
    pthread_join(m_elfThread, &value);

    return true;
}

void Line::elfMain(int argc, char** argv)
{
    LineProcess* process = new LineProcess(this, &m_elfBinary);

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

    process->start(argc, argv);
}

void Line::signal()
{
    pthread_cond_signal(&m_cond);
}

void Line::waitForSingleStep()
{
    pthread_cond_wait(&m_singleStepCond, &m_singleStepCondMutex);
}

