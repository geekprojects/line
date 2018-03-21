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

#include "line.h"
#include "elfexec.h"
#include "elflibrary.h"
#include "utils.h"
#include "process.h"

using namespace std;

typedef int(*entryFunc_t)();

ElfExec::ElfExec(Line* line) : ElfBinary(line)
{
    m_exec = this;
}

ElfExec::~ElfExec()
{
}

void ElfExec::addLibrary(string name, ElfLibrary* lib)
{
    m_libraryMap.insert(make_pair(name, lib));
}

ElfLibrary* ElfExec::getLibrary(string name)
{
    std::map<string, ElfLibrary*>::iterator it;
    it = m_libraryMap.find(name);
    if (it != m_libraryMap.end())
    {
        return it->second;
    }
    return NULL;
}

void ElfExec::relocateLibraries()
{
    std::map<string, ElfLibrary*>::iterator it;
    for (it = m_libraryMap.begin(); it != m_libraryMap.end(); it++)
    {
        ElfLibrary* lib = it->second;
        lib->relocate();
    }
}

void ElfExec::relocateLibrariesIFuncs()
{
    relocateIFuncs();

    std::map<string, ElfLibrary*>::iterator it;
    for (it = m_libraryMap.begin(); it != m_libraryMap.end(); it++)
    {
        ElfLibrary* lib = it->second;
        lib->relocateIFuncs();
    }
}


/* This calls the entry point.  The SVR4/i386 ABI (pages 3-31, 3-32)
   says that when the entry point runs, most registers' values are
   unspecified, except for:

   %rdx         Contains a function pointer to be registered with `atexit'.
                This is how the dynamic linker arranges to have DT_FINI
                functions called for shared libraries that have been loaded
                before this code runs.

   %rsp         The stack contains the arguments and environment:
                0(%rsp)                         argc
                LP_SIZE(%rsp)                   argv[0]
                ...
                (LP_SIZE*argc)(%rsp)            NULL
                (LP_SIZE*(argc+1))(%rsp)        envp[0]
                ...
                                                NULL
*/

void ElfExec::entry(int argc, char** argv, char** envp)
{
    uint64_t entry = m_header->e_entry + getBase();

    char randbytes[16];
    int i;
    for (i = 0; i < 16; i++)
    {
        randbytes[i] = i;
    }

    // Write the standard stack entry details
    uint64_t* stack = (uint64_t*)alloca(8196); // Allocate from our stack
    uint64_t* stackpos = stack;
    *(stackpos++) = argc;
    for (i = 0; i < argc; i++)
    {
        *(stackpos++) = (uint64_t)argv[i];
    }
    *(stackpos++) = (uint64_t)NULL;
    while (*envp != NULL)
    {
        *(stackpos++) = (uint64_t)*(envp++);
    }
    *(stackpos++) = (uint64_t)NULL;

    // AUX
    *(stackpos++) = AT_PHDR;
    *(stackpos++) = (uint64_t)(m_image + m_header->e_phoff);
    *(stackpos++) = AT_PHENT;
    *(stackpos++) = (uint64_t)(m_image + m_header->e_phentsize);
    *(stackpos++) = AT_PHNUM;
    *(stackpos++) = (uint64_t)(m_image + m_header->e_phnum);
    *(stackpos++) = AT_ENTRY;
    *(stackpos++) = (uint64_t)(m_header->e_entry);
    *(stackpos++) = AT_PAGESZ;
    *(stackpos++) = 4096l;
    *(stackpos++) = AT_RANDOM;
    *(stackpos++) = (uint64_t)randbytes;

    *(stackpos++) = AT_NULL;

    m_line->getProcess()->getPatcher()->patch(entry);

    asm volatile (
        "movq %0, %%rsp\n"
        "movq %2, %%rdx\n"
        "jmpq *%1\n"
        : : "r" (stack), "r" (entry), "r" ((void*)0) : "rdx", "rsp"
    );
}

