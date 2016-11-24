 
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

    printf("ElfLibrary::map: %s\n", m_path);

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

    printf("ElfLibrary::map: loadMin=0x%x, loadMax=0x%x\n", loadMin, loadMax);
    m_base = (uint64_t)mmap(
        (void*)0x40000000,
        loadMax,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANON | MAP_PRIVATE,
        -1,
        0);
 
    for (i = 0; i < m_header->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
        {

            uint64_t start = phdr[i].p_vaddr + loadMin;
            size_t len = ALIGN(phdr[i].p_memsz + ELF_PAGEOFFSET(phdr->p_vaddr), 4096);
            start += m_base;

            printf(
                "ElfLibrary::map: Specified: 0x%llx-0x%llx, Remapped: 0x%llx, 0x%llx, Copying to: 0x%llx, 0x%llx\n",
                phdr[i].p_vaddr,
                phdr[i].p_vaddr + phdr[i].p_memsz,
                start,
                start + len,
                start,
                start + phdr[i].p_filesz);

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
        printf(
            "ElfLibrary::map: Clearing BSS: addr=0x%llx-0x%llx, size=%llu\n",
            bssSection->sh_addr,
            bssSection->sh_addr + bssSection->sh_size - 1,
            bssSection->sh_size);
        memset((void*)(m_base + bssSection->sh_addr), 0x0, bssSection->sh_size);
    }
    else
    {
        printf("ElfLibrary::map: Failed to find BSS section\n");
    }
    return true;
}

