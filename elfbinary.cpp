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

#include "elfbinary.h"
#include "elflibrary.h"
#include "elfexec.h"
#include "elfprocess.h"
#include "rtld.h"
#include "utils.h"

using namespace std;

#undef DEBUG_RELOCATE

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

typedef uint64_t(*ifunc_t)();


void rtld_lock_recursive(void*)
{
}

void rtld_unlock_recursive(void*)
{
}

void* dl_find_dso_for_object(void* addr)
{
    return NULL;
}

rtld_global_ro g_rtldGlobalRO =
{
    ._dl_pagesize = 4096
};

rtld_global g_rtldGlobal =
{
    ._dl_error_catch_tsd = (void**(*)())0xbeefface,
    ._dl_rtld_lock_recursive = rtld_lock_recursive,
    ._dl_rtld_unlock_recursive = rtld_unlock_recursive
};

int __libc_enable_secure = 0;

uint64_t tls_get_addr();

const char* g_libpaths[] =
{
    "root/lib/x86_64-linux-gnu/",
    "root/usr/lib/x86_64-linux-gnu/"
};

ElfBinary::ElfBinary()
{
    m_exec = NULL;
    m_base = 0x0;
    m_tlsSize = 0;
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

    if (!(m_header->e_type == ET_EXEC || m_header->e_type == ET_DYN) || m_header->e_machine != EM_X86_64)
    {
        printf("Unsupported ELF binary\n");
        free(m_image);
        m_image = NULL;
        m_header = NULL;
        return false;
    }

    Elf64_Shdr* sectionHeaderTable = (Elf64_Shdr*)(m_image + m_header->e_shoff);
    m_shStringTable = m_image + sectionHeaderTable[m_header->e_shstrndx - 0].sh_offset;

    Elf64_Shdr* strtabSection;
    strtabSection = findSection(".strtab");
    if (strtabSection == NULL)
    {
        strtabSection = findSection(".dynstr");
    }

    if (strtabSection != NULL)
    {
        m_stringTable = m_image + strtabSection->sh_offset;
    }

    m_symbolSection = findSection(".dynsym");
    if (m_symbolSection == NULL)
    {
        m_symbolSection = findSection(".symtab");
    }

    return true;
}

Elf64_Shdr* ElfBinary::findSection(const char* name)
{
    Elf64_Shdr* sectionHeaderTable = (Elf64_Shdr *) (m_image + m_header->e_shoff);

    int i;
    for (i = 0; i < m_header->e_shnum; i++)
    {
        //printf("ElfHeader::findSection: %d: %s\n", i, m_shStringTable + sectionHeaderTable[i].sh_name);
        if (strcmp(m_shStringTable + sectionHeaderTable[i].sh_name, name) == 0)
        {
            return &(sectionHeaderTable[i]);
        }
    }
    return NULL;
}

const char* ElfBinary::getString(int name)
{
    Elf64_Shdr* symtabSection = findSection(".symtab");
    Elf64_Sym* symtab = (Elf64_Sym*)(m_image + symtabSection->sh_offset);
    return m_stringTable + symtab[name].st_name;
}

Elf64_Sym* ElfBinary::findSymbol(const char* sym)
{
    if (m_symbolSection == NULL)
    {
        return NULL;
    }

    Elf64_Sym* symtab = (Elf64_Sym*)(m_image + m_symbolSection->sh_offset);

    int len = strlen(sym);
    int count = m_symbolSection->sh_size / sizeof(Elf64_Sym);
    int i;
    for (i = 0; i < count; i++)
    {
        const char* name = m_stringTable + symtab[i].st_name;

#if 0
        printf("ElfBinary::findSymbol: %s: %d: st_name=0x%x (%s), info=0x%x, shndx=0x%x, st_value=0x%llx\n",
            m_path,
            i,
            symtab[i].st_name,
            name,
            symtab[i].st_info,
            symtab[i].st_shndx,
            symtab[i].st_value);
#endif

        if (!strncmp(sym, name, len))
        {
            if (name[len] == 0 || name[len] == '@')
            {
/*
        printf("ElfBinary::findSymbol: %s: %d: st_name=0x%x (%s), info=0x%x, shndx=0x%x, st_value=0x%llx\n",
            m_path,
            i,
            symtab[i].st_name,
            name,
            symtab[i].st_info,
            symtab[i].st_shndx,
            symtab[i].st_value);
*/

                return &(symtab[i]);
            }
        }
    }

    return NULL;
}

bool ElfBinary::readDynamicHeader(Elf64_Phdr* header)
{
    Elf64_Dyn* dyn = (Elf64_Dyn*)(m_image + header->p_offset);
    int j;
    for (j = 0; j < header->p_filesz / sizeof(Elf64_Dyn); j++)
    {
        const char* name = "?";
        if (dyn[j].d_tag == DT_NEEDED)
        {
            m_needed.push_back(dyn[j].d_un.d_val);
            name = "NEEDED";
        }

        setDynValue(dyn[j].d_tag, dyn[j].d_un.d_val);

#ifdef DEBUG_DYNAMIC
        if (dyn[j].d_tag == DT_STRTAB)
        {
            name = "STRTAB";
        }
        else if (dyn[j].d_tag == DT_SYMTAB)
        {
            name = "SYMTAB";
        }
        else if (dyn[j].d_tag == DT_JMPREL)
        {
            name = "JMPREL";
        }
        else if (dyn[j].d_tag == DT_PLTRELSZ)
        {
            name = "PLTRELSZ";
        }
        else if (dyn[j].d_tag == DT_RELA)
        {
            name = "RELA";
        }
        else if (dyn[j].d_tag == DT_RELASZ)
        {
            name = "RELSZ";
        }
        else if (dyn[j].d_tag == DT_INIT)
        {
            name = "INIT";
        }

        printf("ElfBinary::readDynamicHeader: %s: %s (%lld) = 0x%llx\n", m_path, name, dyn[j].d_tag, dyn[j].d_un.d_val);
#endif
    }

    return true;
}

bool ElfBinary::map()
{
    bool res;

    if (m_header->e_type == ET_EXEC)
    {
        res = mapStatic();
    }
    else if (m_header->e_type == ET_DYN)
    {
        res = mapDynamic();
    }
    else
    {
        printf("ElfBinary::map: Unhandled ELF type: %d\n", m_header->e_type);
        exit(255);
    }

    if (res)
    {
        Elf64_Shdr* bssSection = findSection(".bss");
        if (bssSection != NULL)
        {
#ifdef DEBUG
            printf(
                "ElfBinary::map: %s: Clearing BSS: addr=0x%llx-0x%llx, size=%llu\n",
                m_path,
                m_base + bssSection->sh_addr,
                m_base + bssSection->sh_addr + bssSection->sh_size - 1,
                bssSection->sh_size);
#endif
            memset((void*)(m_base + bssSection->sh_addr), 0x0, bssSection->sh_size);
        }
        else
        {
            printf("ElfBinary::mapDynamic: %s: Failed to find BSS section\n", m_path);
        }
    }

    return res;
}

bool ElfBinary::mapStatic()
{
    int i;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    m_end = 0;

    for (i = 0; i < m_header->e_phnum; i++)
    {
#ifdef DEBUG
        printf("ElfBinary::mapStatic: Program Header: %d: type=0x%x, flags=0x%x\n", i, phdr[i].p_type, phdr[i].p_flags);
#endif
        if (phdr[i].p_type == PT_LOAD)
        {

            uint64_t start = ELF_ALIGNDOWN(phdr[i].p_vaddr);
            size_t len = ELF_ALIGNUP(phdr[i].p_memsz + ELF_ALIGNUP(phdr->p_vaddr)) - ELF_ALIGNDOWN(phdr->p_vaddr);

#ifdef DEBUG
            printf(
                "ElfBinary::mapStatic: Specified: 0x%llx-0x%llx, Aligned: 0x%llx-0x%llx\n",
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
                printf("ElfBinary::mapStatic: Program Header: %d:  -> maddr=%p, errno=%d\n", i, maddr, err);
                return 1;
            }

#ifdef DEBUG
            printf("ElfBinary::mapStatic: Program Header: %d: memcpy(0x%llx-0x%llx, 0x%llx-0x%llx, %d)\n",
                i,
                (void*)((uint64_t)maddr + ELF_PAGEOFFSET(phdr[i].p_vaddr)),
                (uint64_t)maddr + ELF_PAGEOFFSET(phdr[i].p_vaddr) + phdr[i].p_filesz,
                m_image + phdr[i].p_offset,
                m_image + phdr[i].p_offset + phdr[i].p_filesz,
                phdr[i].p_filesz);
#endif
            memcpy(
                (void*)((uint64_t)maddr + ELF_PAGEOFFSET(phdr[i].p_vaddr)),
                m_image + phdr[i].p_offset,
                phdr[i].p_filesz);

            if (phdr[i].p_vaddr + phdr[i].p_memsz > m_end)
            {
                m_end = ELF_ALIGNUP(phdr[i].p_vaddr + phdr[i].p_memsz);
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

    return true;
}

bool ElfBinary::mapDynamic()
{
    int i;

#ifdef DEBUG
    printf("ElfBinary::mapDynamic: %s\n", m_path);
#endif

    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    uint64_t loadMin = 0;
    uint64_t loadMax = 0;

    Elf64_Shdr* shdr = (Elf64_Shdr*)(m_image + m_header->e_shoff);
    for (i = 0; i < m_header->e_shnum; i++)
    {
        if (shdr[i].sh_flags & SHF_ALLOC)
        {
            uint64_t min = (shdr[i].sh_addr & ~0xfff);
            uint64_t max = min + ALIGN(shdr[i].sh_size + ELF_PAGEOFFSET(shdr[i].sh_addr), 4096);
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
    printf("ElfBinary::mapDynamic: %s: loadMin=0x%llx, loadMax=0x%llx\n", m_path, loadMin, loadMax);
#endif

    uint64_t loadAddr = m_elfProcess->getNextLibraryLoadAddr();
#ifdef DEBUG
    printf("ElfBinary::mapDynamic: %s: loadAddr=0x%llx\n", m_path, loadAddr);
#endif

    // Allocate a base location for this library now we know how big it is
    m_base = (uint64_t)mmap(
        (void*)loadAddr,
        loadMax,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANON | MAP_PRIVATE,
        -1,
        0);

#ifdef DEBUG
    printf("ElfBinary::mapDyanmic: m_base=0x%llx\n", m_base);
#endif

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
                "ElfBinary::mapDynamic: %s: Specified: 0x%llx-0x%llx, Remapped: 0x%llx, 0x%llx, Copying to: 0x%llx, 0x%llx\n",
                m_path,
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
    return true;
}

bool ElfBinary::loadLibraries()
{
    const char* strtab = (const char*)(getDynValue(DT_STRTAB) + m_base);

#ifdef DEBUG
    printf("ElfBinary::loadLibraries: %s: strtab: 0x%llx-0x%llx\n", m_path, getDynValue(DT_STRTAB), getDynValue(DT_STRTAB) + getDynValue(DT_STRSZ) - 1);
#endif

    vector<uint64_t>::iterator it;
    for (it = m_needed.begin(); it != m_needed.end(); it++)
    {
        uint64_t needed = *it;
        const char* nameChar = strtab + needed;

#ifdef DEBUG
        printf("ElfBinary::loadLibraries: %s: needed=%lld: 0x%llx\n", m_path, needed, nameChar);
#endif

        string name = string(strtab + needed);

        if (name == "ld-linux-x86-64.so.2")
        {
#ifdef DEBUG
            printf("ElfBinary::loadLibraries:  -> Loader, skipping\n");
#endif
            continue;
        }

        ElfLibrary* library = m_exec->getLibrary(name);
        if (name.length() > 0)
        {
            library = m_exec->getLibrary(name);
        }
        else
        {
#ifdef DEBUG
            printf("ElfBinary::loadLibraries:  -> This library???\n");
#endif
            library = (ElfLibrary*)this;
        }
#ifdef DEBUG
        printf("ElfBinary::loadLibraries: %s:  -> library=%p\n", m_path, library);
#endif

        if (library == NULL)
        {
            library = new ElfLibrary(m_exec);
            library->setElfProcess(m_elfProcess);
            m_exec->addLibrary(name, library);

            bool res = false;
            int i;
            for (i = 0; i < sizeof(g_libpaths) / sizeof(char*); i++)
            {
                string libpath = string(g_libpaths[i]) + name;
#ifdef DEBUG
                printf("ElfBinary::loadLibraries: %s: %s -> %s\n", m_path, name.c_str(), libpath.c_str());
#endif

#ifdef DEBUG
                printf("ElfBinary::loadLibraries: %s: LOADING %s -> %s\n", m_path, name.c_str(), libpath.c_str());
#endif

                res = library->load(libpath.c_str());
                if (res)
                {
                    break;
                }
            }

            if (!res)
            {
                printf("ElfBinary::loadLibraries: %s: Failed to find library: %s\n", m_path, name.c_str());
                return false;
            }

            res = library->map();
            if (!res)
            {
                printf("ElfBinary::loadLibraries: %s: Failed to map library: %s\n", m_path, name.c_str());
                return false;
            }

            res = library->loadLibraries();
            if (!res)
            {
                printf("ElfBinary::loadLibraries: %s: Failed to load libraries: %s\n", m_path, name.c_str());
                return false;
            }
        }
    }

    return true;
}

bool ElfBinary::relocate()
{
    uint64_t base = getBase();
    //const char* name = lib->getDynName() + base;
    Elf64_Rela* jmprel = (Elf64_Rela*)(getDynValue(DT_JMPREL) + base);
    int jmprelcount = getDynValue(DT_PLTRELSZ) / sizeof(Elf64_Rela);

    Elf64_Sym* symtab = (Elf64_Sym*)(getDynValue(DT_SYMTAB) + base);
    const char* strtab = (const char*)(getDynValue(DT_STRTAB) + base);

    int i;
    bool relocated;
    for (i = 0; i < jmprelcount; i++)
    {
        relocateRela(&(jmprel[i]), base, symtab, strtab);
    }

    Elf64_Rela* rela = (Elf64_Rela*)(getDynValue(DT_RELA) + base);
    int relacount = getDynValue(DT_RELASZ) / sizeof(Elf64_Rela);

    for (i = 0; i < relacount; i++)
    {
        relocateRela(&(rela[i]), base, symtab, strtab);
    }

    return true;
}

bool ElfBinary::relocateIFuncs()
{
    int i;
    uint64_t base = getBase();

    Elf64_Sym* symtab = (Elf64_Sym*)(getDynValue(DT_SYMTAB) + base);
    const char* strtab = (const char*)(getDynValue(DT_STRTAB) + base);

    vector<IFuncRela>::iterator it;
    for (it = m_ifuncRelas.begin(); it != m_ifuncRelas.end(); it++)
    {
        IFuncRela rela = *it;

        uint64_t destaddr = rela.rela->r_offset + base;
        uint64_t* dest64 = (uint64_t*)destaddr;
        switch (ELF64_R_TYPE(rela.rela->r_info))
        {
            case R_X86_64_IRELATIVE:
            {
                if (rela.lib == NULL)
                {
                    printf("ElfBinary::relocateIFuncs: R_X86_64_IRELATIVE: lib is NULL!\n");
                    exit(255);
                }
                ifunc_t ifunc = (ifunc_t)(rela.lib->getBase() + rela.rela->r_addend);
#ifdef DEBUG_RELOCATE
                printf(
                    "ElfBinary::relocateRela: R_X86_64_IRELATIVE: ifunc value=0x%llx\n",
                    ifunc);
#endif

                uint64_t value = ifunc();
#ifdef DEBUG_RELOCATE
                printf(
                    "ElfBinary::relocateRela: %s: R_X86_64_IRELATIVE: ifunc result=0x%llx\n",
                    m_path,
                    value);
#endif

                *dest64 = value;
 
            } break;

            case R_X86_64_JUMP_SLOT:
            {
                if (rela.symbol == NULL)
                {
                    printf("ElfBinary::relocateIFuncs: R_X86_64_JUMP_SLOT: lib is NULL!\n");
                    exit(255);
                }
                int symType = ELF64_ST_TYPE(rela.symbol->st_info);
                if (symType != STT_GNU_IFUNC)
                {
                    printf("ElfBinary::relocateIFuncs: R_X86_64_JUMP_SLOT: Symbol is not STT_GNU_IFUNC\n");
                    exit(255);
                }
                ifunc_t ifunc = (ifunc_t)(rela.lib->getBase() + rela.symbol->st_value);
                *dest64 = ifunc();
            } break;

            case R_X86_64_GLOB_DAT:
            {
                *dest64 = 0xdeadbeef;
            } break;

            default:
                printf("ElfBinary::relocateIFuncs: Unhandled type: %d\n", ELF64_R_TYPE(rela.rela->r_info));
                exit(255);
        }
    }

    return true;
}

void ElfBinary::relocateRela(
    Elf64_Rela* rela,
    uint64_t base,
    Elf64_Sym* symtab,
    const char* strtab)
{
    int sym = rela->r_info >> 32;
    int type = rela->r_info & 0xffffffff;

    bool callIFuncs = false;

    bool isIFunc = (type == R_X86_64_IRELATIVE);
    if (isIFunc && !callIFuncs)
    {
#ifdef DEBUG_RELOCATE
        printf("ElfBinary::relocateRela: %s: Skipping IRELATIVE\n", m_path);
#endif
        IFuncRela ifr;
        ifr.rela = rela;
        ifr.symbol = NULL;
        ifr.lib = this;
        m_ifuncRelas.push_back(ifr);
        return;
    }
    else if (callIFuncs && !(type == R_X86_64_IRELATIVE || type == R_X86_64_JUMP_SLOT))
    {
#ifdef DEBUG_RELOCATE
        printf("ElfBinary::relocateRela: %s: Skipping non-IRELATIVE or JUMP_SLOT\n", m_path);
#endif
        return;
    }

#ifdef DEBUG_RELOCATE
    printf("ElfBinary::relocateRela: %s: offset=%p, info=(sym=%d, type=%d), addend=0x%llx\n",
        m_path,
        rela->r_offset,
        sym,
        type,
        rela->r_addend);
#endif

    Elf64_Sym* symbol = NULL;
    const char* symName = NULL;
    ElfBinary* lib = NULL;
    if (sym != 0 && symbol == NULL)
    {
        symName = strtab + symtab[sym].st_name;

#ifdef DEBUG_RELOCATE
        printf(
            "ElfBinary::relocateRela: %s: Finding symbol: %s\n",
            m_path,
            symName);
#endif

        if (type == R_X86_64_GLOB_DAT)
        {
            symbol = m_exec->findSymbol(symName);
            if (symbol != NULL && symbol->st_value != 0)
            {
                lib = m_exec;
#ifdef DEBUG_RELOCATE
                printf(
                    "ElfBinary::relocateRela: %s: R_X86_64_GLOB_DAT: Found symbol in exec: 0x%llx\n",
                    m_path,
                    symbol->st_value);
#endif
            }
            else
            {
#ifdef DEBUG_RELOCATE
                printf(
                    "ElfBinary::relocateRela: %s: R_X86_64_GLOB_DAT: Unable to find symbol\n",
                    m_path);
#endif
                    symbol = NULL;
            }
        }

        if (lib == NULL)
        {
            std::map<std::string, ElfLibrary*> libs = m_exec->getLibraries();
            std::map<std::string, ElfLibrary*>::iterator it;
            for (it = libs.begin(); it != libs.end() && symbol == NULL; it++)
            {
                lib = it->second;
                symbol = lib->findSymbol(symName);
                if (symbol != NULL && symbol->st_value != 0)
                {
                    break;
                }
                lib = NULL;
                symbol = NULL;
            }
        }

        if (lib != NULL)
        {
#ifdef DEBUG_RELOCATE
            printf(
                "ElfBinary::relocateRela: %s: %s = %p\n",
                m_path,
                lib->getPath(),
                symbol);
#endif
        }
        else
        {
#ifdef DEBUG_RELOCATE
            printf(
                "ElfBinary::relocateRela: %s: Unable to find symbol %s\n",
                m_path,
                symName);
#endif
        }
    }
    else
    {
        lib = this;
    }

    uint64_t symbolValue = 0;
    int symType = 0;
    int symBind = 0;
    if (symbol != NULL)
    {
        symType = ELF64_ST_TYPE(symbol->st_info);
        symBind = ELF64_ST_BIND(symbol->st_info);
    }

#ifdef DEBUG_RELOCATE
        printf(
            "ElfBinary::relocateRela: %s: sym name=%s, sym type=%d, bind=%d\n",
            m_path,
            symName,
            symType,
            symBind);
        printf(
            "ElfBinary::relocateRela: %s: -> symbol=%p\n",
            m_path,
            symbol);
#endif

    if (symbol != NULL)
    {
        if (symType == STT_GNU_IFUNC)
        {
            if (!callIFuncs)
            {
#ifdef DEBUG_RELOCATE
                printf("ElfBinary::relocateRela: %s: Skipping IFUNC\n", m_path);
#endif
                IFuncRela ifuncRela;
                ifuncRela.rela = rela;
                ifuncRela.symbol = symbol;
                ifuncRela.lib = lib;
                m_ifuncRelas.push_back(ifuncRela);
                return;
            }

            ifunc_t ifunc = (ifunc_t)(lib->getBase() + symbol->st_value);
            symbolValue = ifunc();
            isIFunc = true;
        }
        else if (symbol->st_value != 0)
        {
            symbolValue = lib->getBase() + symbol->st_value;
        }
    }

    if (callIFuncs && !isIFunc)
    {
#ifdef DEBUG_RELOCATE
        printf("ElfBinary::relocateRela: %s: Skipping non-IFUNC\n", m_path);
#endif
        return;
    }

    uint64_t destaddr = rela->r_offset + base;
    uint64_t* dest64 = (uint64_t*)destaddr;
    uint32_t* dest32 = (uint32_t*)destaddr;
    switch (type)
    {
        case R_X86_64_COPY:
        {
            if (symbolValue != 0)
            {
#ifdef DEBUG_RELOCATE
                printf(
                    "ElfBinary::relocateRela: R_X86_64_COPY: src=0x%llx, size=%d\n", 
                    symbolValue,
                    symbol->st_size);
#endif
                memcpy((void*)destaddr, (void*)symbolValue, symbol->st_size);
#ifdef DEBUG_RELOCATE
                hexdump((char*)destaddr, symbol->st_size);
#endif
            }
        } break;

        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        {
            if (symbolValue == 0)
            {
                if (!strcmp(symName, "_rtld_global"))
                {
                    symbolValue = (uint64_t)(&g_rtldGlobal);
#ifdef DEBUG_RELOCATE
                    printf(
                        "ElfBinary::relocateRela: R_X86_64_JUMP_SLOT:  -> _rtld_global\n");
#endif
                }
                else if (!strcmp(symName, "_rtld_global_ro"))
                {
                    symbolValue = (uint64_t)(&g_rtldGlobalRO);
#ifdef DEBUG_RELOCATE
                    printf(
                        "ElfBinary::relocateRela: R_X86_64_JUMP_SLOT:  -> _rtld_global_ro\n");
#endif
                }
                else if (!strcmp(symName, "__tls_get_addr"))
                {
                    symbolValue = (uint64_t)(tls_get_addr);
#ifdef DEBUG_RELOCATE
                    printf(
                        "ElfBinary::relocateRela: R_X86_64_JUMP_SLOT:  -> __tls_get_addr\n");
#endif
                }
                else if (!strcmp(symName, "_dl_find_dso_for_object"))
                {
                    symbolValue = (uint64_t)(dl_find_dso_for_object);
#ifdef DEBUG_RELOCATE
                    printf(
                        "ElfBinary::relocateRela: R_X86_64_JUMP_SLOT:  -> _dl_find_dso_for_object\n");
#endif
                }
                else if (!strcmp(symName, "__libc_enable_secure"))
                {
                    symbolValue = (uint64_t)(&__libc_enable_secure);
#ifdef DEBUG_RELOCATE
                    printf(
                        "ElfBinary::relocateRela: R_X86_64_JUMP_SLOT:  -> __libc_enable_secure\n");
#endif
                }


            }
            if (type == R_X86_64_64)
            {
                symbolValue += rela->r_addend;
            }
#ifdef DEBUG_RELOCATE
            printf(
                "ElfBinary::relocateRela: %s: R_X86_64_JUMP_SLOT:  -> 0x%llx = 0x%llx\n",
                m_path,
                destaddr,
                symbolValue);
#endif

            *dest64 = symbolValue;
        } break;

        case R_X86_64_RELATIVE:
        {
            if (lib != NULL)
            {
                *dest64 = (lib->getBase() + rela->r_addend);
#ifdef DEBUG_RELOCATE
                printf(
                    "ElfBinary::relocateRela: R_X86_64_RELATIVE: 0x%llx + 0x%llx = 0x%llx\n", lib->getBase(), rela->r_addend, *dest64);
#endif
            }
        } break;

        case R_X86_64_DTPMOD64:
        {
#ifdef DEBUG
            printf("ElfBinary::relocateRela: R_X86_64_DTPMOD64: 0x%llx\n", m_tlsBase);
#endif
            *dest64 = m_tlsBase;
        } break;

        case R_X86_64_DTPOFF64:
        {
#ifdef DEBUG
            printf(
                "ElfBinary::relocateRela: R_X86_64_DTPOFF64: 0x%llx\n", m_tlsBase);
#endif
            *dest64 = m_tlsBase;
        } break;

        case R_X86_64_TPOFF64:
        {
            *dest64 = ((int)rela->r_addend - m_tlsBase);// + (int64_t)m_elfProcess->getFSPtr();
#ifdef DEBUG_RELOCATE
            printf("ElfBinary::relocateRela: R_X86_64_TPOFF64: %d - %d -> %d\n", rela->r_addend, m_tlsBase, *dest64);
#endif
        } break;

        case R_X86_64_IRELATIVE:
        {
       } break;

        default:
            printf("ElfBinary::relocateRela: Unhandled relocation type: %d\n", type);
            exit(255);
            break;
    }
}

void ElfBinary::initTLS(void* tls)
{
    int i;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    for (i = 0; i < m_header->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_TLS)
        {
#ifdef DEBUG
            printf("ElfBinary::initTLS: Copying 0x%llx -> 0x%llx\n", phdr[i].p_vaddr + getBase(), tls);
#endif
            memcpy(
                tls,
                (void*)(phdr[i].p_vaddr + getBase()),
                phdr[i].p_filesz);
        }
    }
}

