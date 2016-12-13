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
#include "rtld.h"
#include "utils.h"

using namespace std;

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
*/

    Elf64_Shdr* strtabSection;
    if (m_header->e_type == ET_EXEC)
    {
        strtabSection = findSection(".strtab");
    }
    else
    {
        strtabSection = findSection(".dynstr");
    }

    if (strtabSection != NULL)
    {
        m_stringTable = m_image + strtabSection->sh_offset;
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
    Elf64_Shdr* symtabSection;
    if (m_header->e_type == ET_EXEC)
    {
        symtabSection = findSection(".symtab");
    }
    else
    {
        symtabSection = findSection(".dynsym");
    }

    if (symtabSection == NULL)
    {
        printf("ElfBinary::findSymbol: No symtab\n");
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

#ifdef DEBUG
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

#ifdef DEBUG
        printf("ElfBinary::readDynamicHeader: %s: %s (%lld) = 0x%llx\n", m_path, name, dyn[j].d_tag, dyn[j].d_un.d_val);
#endif
#endif
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
#ifdef DEBUG
        printf("ElfBinary::loadLibraries: %s: needed=%lld: 0x%llx\n", m_path, needed, needed + strtab);
#endif

        const char* nameChar = strtab + needed;
        string name = string(strtab + needed);

        string libpath = string("root/lib/") + name;
#ifdef DEBUG
        printf("ElfBinary::loadLibraries: %s: %s -> %s\n", m_path, name.c_str(), libpath.c_str());
#endif

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
#ifdef DEBUG
            printf("ElfBinary::loadLibraries: m_elfProcess=0x%llx\n", m_elfProcess);
#endif
            library->setElfProcess(m_elfProcess);

#ifdef DEBUG
            printf("ElfBinary::loadLibraries: %s: LOADING %s -> %s\n", m_path, name.c_str(), libpath.c_str());
#endif

            bool res;
            res = library->load(libpath.c_str());
            if (!res)
            {
                continue;
            }

            res = library->map();
            if (!res)
            {
                continue;
            }
            m_exec->addLibrary(name, library);

            res = library->loadLibraries();
            if (!res)
            {
                continue;
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

void ElfBinary::relocateRela(Elf64_Rela* rela, uint64_t base, Elf64_Sym* symtab, const char* strtab)
{
    int sym = rela->r_info >> 32;
    int type = rela->r_info & 0xffffffff;

#ifdef DEBUG
    printf("ElfBinary::relocateRela: %s: offset=%p, info=(sym=%d, type=%d), addend=0x%llx\n",
        m_path,
        rela->r_offset,
        sym,
        type,
        rela->r_addend);
#endif

    ElfLibrary* lib = NULL;
    Elf64_Sym* symbol = NULL;
    const char* symName = NULL;
    if (sym > 0)
    {
        symName = strtab + symtab[sym].st_name;

#ifdef DEBUG
        printf(
            "ElfBinary::relocate: %s: Finding symbol: %s\n",
            m_path,
            symName);
#endif

        std::map<std::string, ElfLibrary*>::iterator it;
        for (it = m_exec->getLibraries().begin(); it != m_exec->getLibraries().end(); it++)
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
        if (lib != NULL)
        {
#ifdef DEBUG
            printf(
                "ElfBinary::relocate: %s: %s = %p\n",
                m_path,
                lib->getPath(),
                symbol);
#endif
        }
        else
        {
            printf(
                "ElfBinary::relocate: %s: Unable to find symbol %s\n",
                m_path,
                symName);
        }
    }
    else
    {
        if (m_header->e_type == ET_DYN)
        {
            lib = (ElfLibrary*)this;
        }
    }

    uint64_t destaddr = rela->r_offset + base;
    uint64_t* dest64 = (uint64_t*)destaddr;
    uint32_t* dest32 = (uint32_t*)destaddr;
    switch (type)
    {
        case R_X86_64_COPY:
        {
            if (symbol != NULL)
            {
                const char* symName = strtab + symtab[sym].st_name;

#ifdef DEBUG
                printf(
                    "ElfBinary::relocate: R_X86_64_COPY: sym name=%s, src=0x%llx, size=%d\n", 
                    symName,
                    symbol->st_value + lib->getBase(), symbol->st_size);
#endif
                memcpy((void*)destaddr, (void*)(symbol->st_value + lib->getBase()), symbol->st_size);
                hexdump((char*)destaddr, symbol->st_size);
            }
        } break;

        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        {
            int symType = symtab[sym].st_info & 0xf;
            int symBind = symtab[sym].st_info >> 4;
#ifdef DEBUG
            printf(
                "ElfBinary::relocate: %s: R_X86_64_JUMP_SLOT: sym name=%s, sym type=%d, bind=%d\n",
                m_path,
                symName,
                symType,
                symBind);
            printf(
                "ElfBinary::relocate: %s: R_X86_64_JUMP_SLOT:  -> symbol=%p\n",
                m_path,
                symbol);
#endif
            uint64_t value = 0;
            if (symbol != NULL)
            {
                if (symbol->st_value != 0)
                {
                    value = lib->getBase() + symbol->st_value;
                }
            }
            else
            {
                if (!strcmp(symName, "_rtld_global"))
                {
                    value = (uint64_t)(&g_rtldGlobal);
#ifdef DEBUG
                    printf(
                        "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> _rtld_global\n");
#endif
                }
                else if (!strcmp(symName, "_rtld_global_ro"))
                {
                    value = (uint64_t)(&g_rtldGlobalRO);
#ifdef DEBUG
                    printf(
                        "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> _rtld_global_ro\n");
#endif
                }
                else if (!strcmp(symName, "__tls_get_addr"))
                {
                    value = (uint64_t)(tls_get_addr);
#ifdef DEBUG
                    printf(
                        "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> __tls_get_addr\n");
#endif
                }
                else if (!strcmp(symName, "_dl_find_dso_for_object"))
                {
                    value = (uint64_t)(dl_find_dso_for_object);
#ifdef DEBUG
                    printf(
                        "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> _dl_find_dso_for_object\n");
#endif
                }
                else if (!strcmp(symName, "__libc_enable_secure"))
                {
value = (uint64_t)(&__libc_enable_secure);
#ifdef DEBUG
                    printf(
                        "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> __libc_enable_secure\n");
#endif
                }


            }
            if (type == R_X86_64_64)
            {
                value += rela->r_addend;
            }
#ifdef DEBUG
                printf(
                    "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> value=0x%llx\n",
                    value);
#endif

            *dest64 = value;
        } break;

        case R_X86_64_RELATIVE:
        {
            if (lib != NULL)
            {
                *dest64 = (lib->getBase() + rela->r_addend);
#ifdef DEBUG
                printf(
                    "ElfBinary::relocate: R_X86_64_IRELATIVE: 0x%llx + 0x%llx = 0x%llx\n", lib->getBase(), rela->r_addend, *dest64);
#endif
            }
        } break;

        case R_X86_64_DTPMOD64:
            {
            *dest64 = m_tlsBase;
        } break;

        case R_X86_64_TPOFF64:
        {
            *dest64 = m_tlsBase + rela->r_addend;
#ifdef DEBUG
            printf("ElfBinary::relocate: R_X86_64_TPOFF64: m_tlsBase=0x%llx -> 0x%llx\n", m_tlsBase, *dest64);
#endif
        } break;

        case R_X86_64_IRELATIVE:
        {
            if (lib != NULL)
            {
                ifunc_t ifunc = (ifunc_t)(lib->getBase() + rela->r_addend);
#ifdef DEBUG
                printf(
                    "ElfBinary::relocate: R_X86_64_IRELATIVE: ifunc value=0x%llx\n",
                    ifunc);
#endif
/*
uint64_t value = ifunc();
            printf(
                "ElfBinary::relocate: %s: R_X86_64_IRELATIVE: ifunc result=0x%llx\n",
                name,
value);
*/
                *dest64 = (lib->getBase() + rela->r_addend);
            }
        } break;

        default:
            printf("ElfBinary::relocate: Unhandled relocation type: %d\n", type);
            break;
    }
}

void ElfBinary::initTLS(void* tls)
{
    int i;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    uint64_t base = 0;
    if (m_header->e_type == ET_DYN)
    {
        base = ((ElfLibrary*)this)->getBase();
    }

    for (i = 0; i < m_header->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_TLS)
        {
            memcpy(
                tls,
                (void*)(phdr[i].p_vaddr + base),
                phdr[i].p_filesz);
        }
    }
}

