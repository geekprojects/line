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
#include "process.h"

using namespace std;

ElfLibrary::ElfLibrary(Line* line, ElfExec* exec) : ElfBinary(line)
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

        m_line->getProcess()->patchCode(entry);

        initFunc(argc, argv, envp);
    }

    uint64_t* initArray = (uint64_t*)(getDynValue(DT_INIT_ARRAY) + getBase());
    uint64_t initArraySize = getDynValue(DT_INIT_ARRAYSZ);
#ifdef DEBUG
    printf("ElfLibrary::entry: initArray=%p, initArraySize=%lld\n", initArray, initArraySize);
#endif
    if (initArray != NULL)
    {
        int i;
        for (i = 0; i < initArraySize / 8; i++)
        {
#ifdef DEBUG
            printf("ElfLibrary::entry:  -> 0x%llx\n", initArray[i]);
#endif
            if (initArray[i] != 0)
            {
                initFunc_t initFunc = (initFunc_t)initArray[i];
                m_line->getProcess()->patchCode((uint64_t)initFunc);
                initFunc(argc, argv, envp);
            }
        }
    }
}

