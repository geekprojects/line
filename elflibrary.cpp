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

using namespace std;

ElfLibrary::ElfLibrary(ElfExec* exec)
{
    m_exec = exec;
}

ElfLibrary::~ElfLibrary()
{
}

bool ElfLibrary::map()
{
    int i;

#ifdef DEBUG
    printf("ElfLibrary::map: %s\n", m_path);
#endif

    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    uint64_t loadMin = 0;
    uint64_t loadMax = 0;
    for (i = 0; i < m_header->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
        {
            uint64_t min = (phdr[i].p_vaddr & ~0xfff);
            uint64_t max = min + ALIGN(phdr[i].p_memsz + ELF_PAGEOFFSET(phdr->p_vaddr), 4096);
            if (i == 0)
            {
                loadMin = min;
                loadMax = max;
            }
            else
            {
                if (min < loadMin)
                {
                    loadMin = min;
                }
                if (max > loadMax)
                {
                    loadMax = max;
                }
            }
        }
    }

#ifdef DEBUG
    printf("ElfLibrary::map: loadMin=0x%llx, loadMax=0x%llx\n", loadMin, loadMax);
#endif

    // Allocate a base location for this library now we know how big it is
    m_base = (uint64_t)mmap(
        (void*)0x40000000,
        loadMax,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANON | MAP_PRIVATE,
        -1,
        0);
 
    // Now we have a base, we can copy the library to where its new home
    for (i = 0; i < m_header->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
        {

            uint64_t start = phdr[i].p_vaddr + loadMin;
            size_t len = ALIGN(phdr[i].p_memsz + ELF_PAGEOFFSET(phdr->p_vaddr), 4096);
            start += m_base;

#ifdef DEBUG
            printf(
                "ElfLibrary::map: Specified: 0x%llx-0x%llx, Remapped: 0x%llx, 0x%llx, Copying to: 0x%llx, 0x%llx\n",
                phdr[i].p_vaddr,
                phdr[i].p_vaddr + phdr[i].p_memsz,
                start,
                start + len,
                start,
                start + phdr[i].p_filesz);
#endif

            memcpy(
                (void*)start,
                m_image + phdr[i].p_offset,
                phdr[i].p_filesz);
        }
        else if (phdr[i].p_type == PT_DYNAMIC)
        {
            readDynamicHeader(&(phdr[i]));
        }
        else if (phdr[i].p_type == PT_TLS)
        {
            m_tlsSize = phdr[i].p_memsz;
        }
    }

    Elf64_Shdr* bssSection = findSection(".bss");
    if (bssSection != NULL)
    {
#ifdef DEBUG
        printf(
            "ElfLibrary::map: Clearing BSS: addr=0x%llx-0x%llx, size=%llu\n",
            bssSection->sh_addr,
            bssSection->sh_addr + bssSection->sh_size - 1,
            bssSection->sh_size);
#endif
        memset((void*)(m_base + bssSection->sh_addr), 0x0, bssSection->sh_size);
    }
    else
    {
        printf("ElfLibrary::map: Failed to find BSS section\n");
    }
    return true;
}

