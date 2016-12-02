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

#include "elfexec.h"
#include "utils.h"

using namespace std;

#define DEBUG

typedef int(*entryFunc_t)();

ElfExec::ElfExec()
{
    m_exec = this;
}

ElfExec::~ElfExec()
{
}

void ElfExec::addLibrary(string name, ElfLibrary* lib)
{
    m_libraries.insert(make_pair(name, lib));
}

ElfLibrary* ElfExec::getLibrary(string name)
{
    std::map<string, ElfLibrary*>::iterator it;
    it = m_libraries.find(name);
    if (it != m_libraries.end())
    {
        return it->second;
    }
    return NULL;
}

bool ElfExec::map()
{
    int i;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    m_end = 0;

    for (i = 0; i < m_header->e_phnum; i++)
    {
#ifdef DEBUG
        printf("ElfExec::map: Program Header: %d: type=0x%x, flags=0x%x\n", i, phdr[i].p_type, phdr[i].p_flags);
#endif
        if (phdr[i].p_type == PT_LOAD)
        {

            uint64_t start = ELF_ALIGNDOWN(phdr[i].p_vaddr);
            size_t len = ELF_ALIGNUP(phdr[i].p_memsz + ELF_ALIGNUP(phdr->p_vaddr)) - ELF_ALIGNDOWN(phdr->p_vaddr);

#ifdef DEBUG
            printf(
                "ElfExec::map: Specified: 0x%llx-0x%llx, Aligned: 0x%llx-0x%llx\n",
                phdr[i].p_vaddr,
                phdr[i].p_vaddr + phdr[i].p_memsz,
                start,
                start + len);
#endif

            int prot = PROT_READ | PROT_WRITE;
            if (phdr[i].p_flags & PF_X)
            {
                prot |= PROT_EXEC;
            }

            int flags = MAP_ANON | MAP_PRIVATE;
            if (start != 0)
            {
                flags |= MAP_FIXED;
            }

            void* maddr = mmap(
                (void*)start,
                len,
                prot,
                flags,
                -1,
                0);
            int err = errno;

            if (maddr == (void*)-1)
            {
                printf("ElfExec::map: Program Header: %d:  -> maddr=%p, errno=%d\n", i, maddr, err);
                return 1;
            }

            printf("ElfExec::map: Program Header: %d: memcpy(0x%llx-0x%llx, 0x%llx-0x%llx, %d)\n",
                i,
                (void*)((uint64_t)maddr + ELF_PAGEOFFSET(phdr[i].p_vaddr)),
                (uint64_t)maddr + ELF_PAGEOFFSET(phdr[i].p_vaddr) + phdr[i].p_filesz,
                m_image + phdr[i].p_offset,
                m_image + phdr[i].p_offset + phdr[i].p_filesz,
                phdr[i].p_filesz);
            memcpy(
                (void*)((uint64_t)maddr + ELF_PAGEOFFSET(phdr[i].p_vaddr)),
                m_image + phdr[i].p_offset,
                phdr[i].p_filesz);

            if (phdr[i].p_vaddr + phdr[i].p_memsz > m_end)
            {
                m_end = ELF_ALIGNUP(phdr[i].p_vaddr);
            }
        }
        else if (phdr[i].p_type == PT_TLS)
        {
            m_tlsSize = phdr[i].p_memsz;
        }
        else if (phdr[i].p_type == PT_DYNAMIC)
        {
            readDynamicHeader(&(phdr[i]));
        }
    }

    Elf64_Shdr* bssSection = findSection(".bss");
    if (bssSection != NULL)
    {
#ifdef DEBUG
        printf(
            "ElfExec::map: Clearing BSS: addr=0x%llx-0x%llx, size=%llu\n",
            bssSection->sh_addr,
            bssSection->sh_addr + bssSection->sh_size - 1,
            bssSection->sh_size);
#endif
        memset((void*)bssSection->sh_addr, 0x0, bssSection->sh_size);
    }
    else
    {
        printf("ElfExec::map: Failed to find BSS section\n");
    }
    return true;
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

static void exitfunction()
{
}

void ElfExec::entry(int argc, char** argv, char** envp)
{
    entryFunc_t entry = (entryFunc_t)(m_header->e_entry);
    char randbytes[16];
    int i;
    for (i = 0; i < 16; i++)
    {
        randbytes[i] = i;
    }

    // Write the standard stack entry details
    uint64_t* stack = (uint64_t*)alloca(4096); // Allocate from our stack
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

    asm volatile (
        "movq %0, %%rsp\n"
        "movq %2, %%rdx\n"
        "jmp *%1\n"
        : : "r" (stack), "r" (entry), "r" (exitfunction) : "rdx", "rsp"
    );
}

