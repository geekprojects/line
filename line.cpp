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

Line::Line()
{
}

Line::~Line()
{
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

bool Line::execute(int argc, char** argv)
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

    return true;
}

