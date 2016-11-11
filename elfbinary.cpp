 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <arpa/inet.h>

#include "elfbinary.h"
#include "utils.h"

typedef int(*entryFunc_t)();

ElfBinary::ElfBinary()
{
}

ElfBinary::~ElfBinary()
{
}

bool ElfBinary::load(const char* path)
{
    FILE* fp;
    fp = fopen(path, "r");
    if (fp == NULL)
    {
        printf("ElfBinary::load: Unable to open %s\n", path);
        return false;
    }

    m_path = strdup(path);

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    m_image = (char*)malloc(size);
    fread(m_image, 1, size, fp);
    fclose(fp);

    m_header = (Elf64_Ehdr*)m_image;
    //printf("ELF type: 0x%x, machine: 0x%x\n", m_header->e_type, m_header->e_machine);

    if (m_header->e_type != ET_EXEC || m_header->e_machine != EM_X86_64)
    {
        printf("Unsupported ELF binary\n");
        free(m_image);
        m_image = NULL;
        m_header = NULL;
        return false;
    }

    Elf64_Shdr* sectionHeaderTable = (Elf64_Shdr*)(m_image + m_header->e_shoff);
    m_shStringTable = m_image + sectionHeaderTable[m_header->e_shstrndx - 0].sh_offset;

/*
    printf("ELF Image: %p\n", m_image);
    printf("e_shnum=%d, shoff=%lld\n", m_header->e_shnum, m_header->e_shoff);
    printf("e_phnum=%d, phoff=%lld\n", m_header->e_phnum, m_header->e_phoff);
    printf("e_flags=%d\n", m_header->e_flags);
    printf("EI_CLASS=%d\n", m_header->e_ident[EI_CLASS]);
    printf("EI_DATA=%d\n", m_header->e_ident[EI_DATA]);
    printf("EI_VERSION=%d\n", m_header->e_ident[EI_VERSION]);
    printf("EI_OSABI=%d\n", m_header->e_ident[EI_OSABI]);
    printf("String Table: e_shstrndx: %d, offset: %lld\n", m_header->e_shstrndx, sectionHeaderTable[m_header->e_shstrndx].sh_offset);
    printf("Section String table: %p (%s)\n", m_shStringTable, m_stringTable);
*/
#if 0
    // Find the Symbol table
    int i;
    for (i = 0; i < m_header->e_shnum; i++)
    {
        char* sectionName = m_shStringTable + sectionHeaderTable[i].sh_name;
        printf(
            "Section %d: %s (%d), type=%d, flags=%lld, size=%llx\n",
            i,
            sectionName,
            sectionHeaderTable[i].sh_name,
            sectionHeaderTable[i].sh_type,
            sectionHeaderTable[i].sh_flags,
            sectionHeaderTable[i].sh_size);
    }
#endif

    Elf64_Shdr* strtabSection = findSection(".strtab");
    m_stringTable = m_image + strtabSection->sh_offset;

//findSymbol("main");

    return true;
}

Elf64_Shdr* ElfBinary::findSection(const char* name)
{
    Elf64_Shdr* sectionHeaderTable = (Elf64_Shdr *) (m_image + m_header->e_shoff);

    int i;
    for (i = 0; i < m_header->e_shnum; i++)
    {
        //printf("ElfHeader::findSection: %d: %s\n", i, m_stringTable + sectionHeaderTable[i].sh_name);
        if (strcmp(m_shStringTable + sectionHeaderTable[i].sh_name, name) == 0)
        {
            return &(sectionHeaderTable[i]);
        }
    }
    return NULL;
}

Elf64_Sym* ElfBinary::findSymbol(const char* sym)
{
    Elf64_Shdr* symtabSection = findSection(".symtab");
    if (symtabSection == NULL)
    {
        return NULL;
    }

    Elf64_Sym* symtab = (Elf64_Sym*)(m_image + symtabSection->sh_offset);

    int count = symtabSection->sh_size / sizeof(Elf64_Sym);
    int i;
    for (i = 0; i < count; i++)
    {
        const char* name = m_stringTable + symtab[i].st_name;

/*
        printf("ElfBinary::findSymbol: %d: st_name=0x%x (%s), info=0x%x, shndx=0x%x, st_value=0x%llx\n",
            i,
            symtab[i].st_name,
            name,
            symtab[i].st_info,
            symtab[i].st_shndx,
            symtab[i].st_value);
*/
if (!strcmp(sym, name))
{
return &(symtab[i]);
}
    }

    return NULL;
}

void ElfBinary::checkSymbol(const char* sym)
{
    Elf64_Shdr* symtabSection = findSection(".symtab");
    if (symtabSection == NULL)
    {
        return;
    }

    Elf64_Sym* symtab = (Elf64_Sym*)(m_image + symtabSection->sh_offset);

    int count = symtabSection->sh_size / sizeof(Elf64_Sym);
    int i;
    for (i = 0; i < count; i++)
    {
        const char* name = m_stringTable + symtab[i].st_name;

/*
        printf("ElfBinary::findSymbol: %d: st_name=0x%x (%s), info=0x%x, shndx=0x%x, st_value=0x%llx\n",
            i,
            symtab[i].st_name,
            name,
            symtab[i].st_info,
            symtab[i].st_shndx,
            symtab[i].st_value);
*/
if (!strcmp(sym, name))
{
uint64_t* valueAddr = (uint64_t*)(symtab[i].st_value);
printf("ElfBinary::checkSymbol: %s: value=0x%llx, valueAtAddr=0x%llx\n", name, symtab[i].st_value, *valueAddr);
}
    }

}


bool ElfBinary::map()
{
    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    int i;
    for (i = 0; i < m_header->e_phnum; i++)
    {
        printf("Program Header: %d: type=0x%x, flags=0x%x\n", i, phdr[i].p_type, phdr[i].p_flags);
        if (phdr[i].p_type == PT_LOAD)
        {
            uint64_t start = (phdr[i].p_vaddr & ~0xfff);
            size_t len = ALIGN(phdr[i].p_memsz + ELF_PAGEOFFSET(phdr->p_vaddr), 4096);

            printf("ElfBinary::map: Specified: 0x%llx-0x%llx, Aligned: 0x%llx, 0x%llx\n", phdr[i].p_vaddr, phdr[i].p_vaddr + phdr[i].p_memsz, start, start + len);

            int prot = PROT_READ | PROT_WRITE;
            if (phdr[i].p_flags & PF_X)
            {
                prot |= PROT_EXEC;
            }

            void* maddr = mmap(
                (void*)start,
                len,
                prot,
                MAP_FIXED | MAP_ANON | MAP_PRIVATE,
                -1,
                0);

            int err = errno;
            if (maddr == (void*)-1)
            {
                printf("Program Header: %d:  -> maddr=%p, errno=%d\n", i, maddr, err);
                return 1;
            }

            memcpy(
                (void*)(phdr[i].p_vaddr),
                m_image + phdr[i].p_offset,
                phdr[i].p_filesz);
        }
        else if (phdr[i].p_type == PT_TLS)
{
//memset((void*)(phdr[i].p_vaddr), 0, phdr[i].p_memsz);
            memcpy(
                (void*)(phdr[i].p_vaddr),
                m_image + phdr[i].p_offset,
                phdr[i].p_filesz);
hexdump((char*)(phdr[i].p_vaddr), phdr[i].p_filesz);
}
    }

    Elf64_Shdr* bssSection = findSection(".bss");
    if (bssSection != NULL)
    {
        printf("ElfBinary::map: Clearing BSS: addr=0x%llx-0x%llx, size=%d\n", bssSection->sh_addr, bssSection->sh_addr + bssSection->sh_size - 1, bssSection->sh_size);
        memset((void*)bssSection->sh_addr, 0x0, bssSection->sh_size);
    }
    else
    {
        printf("ElfBinary::map: Failed to find BSS section\n");
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

void ElfBinary::entry(int argc, char** argv, char** envp)
{
//const char* argv0 = "hello";
    //register entryFunc_t entry __asm__("rdi"); // Prevent clashes with rdx
    //entry = (entryFunc_t)(m_header->e_entry);

    entryFunc_t entry = (entryFunc_t)(m_header->e_entry);
    char randbytes[16];
    int i;
    for (i = 0; i < 16; i++)
    {
        randbytes[i] = i;
    }

    // Write the standard stack entry details
    uint64_t* stack = (uint64_t*)alloca(4096);
    uint64_t* stackpos = stack;
    *(stackpos++) = argc;
    for (i = 0; i < argc; i++)
    {
        *(stackpos++) = (uint64_t)argv[i];
    }
    *(stackpos++) = NULL;
    while (*envp != NULL)
    {
        *(stackpos++) = (uint64_t)*(envp++);
    }
    *(stackpos++) = NULL;

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

