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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <arpa/inet.h>

#include <string>

#include "elflibrary.h"
#include "elfprocess.h"

using namespace std;

ElfLibrary::ElfLibrary(ElfExec* exec)
{
    m_exec = exec;
}

ElfLibrary::~ElfLibrary()
{
}

typedef void(*initFunc_t)(int argc, char **argv, char **envp);

void ElfLibrary::entry(int argc, char** argv, char** envp)
{
    uint64_t entry = getDynValue(DT_INIT);
    if (entry != 0)
    {
        entry += getBase();
        initFunc_t initFunc = (initFunc_t)entry;
        initFunc(argc, argv, envp);
    }
}

