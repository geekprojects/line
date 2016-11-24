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
#include "utils.h"

using namespace std;

#undef DEBUG

typedef int(*entryFunc_t)();

typedef uint64_t(*ifunc_t)();

struct r_scope_elem
{
  /* Array of maps for the scope.  */
  void* r_list;
  /* Number of entries in the scope.  */
  unsigned int r_nlist;
};



struct rtld_global_ro
{
  int _dl_debug_mask;
  unsigned int _dl_osversion;
  const char *_dl_platform;
  size_t _dl_platformlen;
  size_t _dl_pagesize;
  int _dl_inhibit_cache;
  struct r_scope_elem _dl_initial_searchlist;
  int _dl_clktck;
  int _dl_verbose;
  int _dl_debug_fd;
  int _dl_lazy;
  int _dl_bind_not;
  int _dl_dynamic_weak;
  unsigned int _dl_fpu_control;
  int _dl_correct_cache_id;
  uint64_t _dl_hwcap;
  uint64_t _dl_hwcap_mask;
};

rtld_global_ro g_rtldGlobal;

uint64_t tls_get_addr();

ElfBinary::ElfBinary()
{
    m_exec = NULL;
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
    LibraryEntry* library = NULL;
    Elf64_Dyn* dyn = (Elf64_Dyn*)(m_image + header->p_offset);
    int j;
    for (j = 0; j < header->p_filesz / sizeof(Elf64_Dyn); j++)
    {
        //printf("ElfBinary::readDynamicHeader: %d: %lld = 0x%llx\n", j, dyn[j].d_tag, dyn[j].d_un.d_val);
        if (dyn[j].d_tag == DT_NEEDED)
        {
            //printf("ElfBinary::readDynamicHeader:  -> NEEDED: %lld\n", dyn[j].d_un.d_val);
            library = new LibraryEntry();
            m_libraries.push_back(library);
        }

        if (library == NULL)
        {
            printf("ElfBinary::readDynamicHeader: WARNING: library is null?\n");
            continue;
        }
        library->setDynValue(dyn[j].d_tag, dyn[j].d_un.d_val);

#ifdef DEBUG
        if (dyn[j].d_tag == DT_STRTAB)
        {
            printf("ElfBinary::readDynamicHeader  -> STRTAB: 0x%llx\n", dyn[j].d_un.d_val);
        }
        else if (dyn[j].d_tag == DT_SYMTAB)
        {
            printf("ElfBinary::readDynamicHeader  -> SYMTAB: 0x%llx\n", dyn[j].d_un.d_val);
        }
        else if (dyn[j].d_tag == DT_JMPREL)
        {
            printf("ElfBinary::readDynamicHeader  -> JMPREL: 0x%llx\n", dyn[j].d_un.d_ptr);
        }
        else if (dyn[j].d_tag == DT_PLTRELSZ)
        {
            printf("ElfBinary::readDynamicHeader  -> PLTRELSZ: 0x%llx\n", dyn[j].d_un.d_val);
        }
        else if (dyn[j].d_tag == DT_RELA)
        {
            printf("ElfBinary::readDynamicHeader  -> RELA: 0x%llx\n", dyn[j].d_un.d_val);
        }
        else if (dyn[j].d_tag == DT_RELASZ)
        {
            printf("ElfBinary::readDynamicHeader  -> RELASZ: 0x%llx\n", dyn[j].d_un.d_val);
        }
#endif
    }
    return true;
}

bool ElfBinary::loadLibraries()
{
    vector<LibraryEntry*>::iterator it;
    for (it = m_libraries.begin(); it != m_libraries.end(); it++)
    {
        LibraryEntry* lib = *it;
        if (lib == NULL)
        {
            printf("ElfBinary::loadLibraries: lib IS NULL!?\n");
        }

        string name = string(lib->getDynName());
        string libpath = string("root/lib/") + name;
#ifdef DEBUG
        printf("ElfBinary::loadLibraries: %s -> %s\n", name.c_str(), libpath.c_str());
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

        if (library == NULL)
        {
            library = new ElfLibrary(m_exec);
#ifdef DEBUG
            printf("ElfBinary::loadLibraries: LOADING %s -> %s\n", lib->getDynName(), libpath.c_str());
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


            res = library->loadLibraries();
            if (!res)
            {
                continue;
            }
            m_exec->addLibrary(name, library);
        }
        lib->setLibrary(library);
    }

    return true;
}

bool ElfBinary::relocate()
{
    vector<LibraryEntry*>::iterator it;
    for (it = m_libraries.begin(); it != m_libraries.end(); it++)
    {
        LibraryEntry* lib = *it;
        int i;

        uint64_t base = 0;
        if (m_header->e_type == ET_DYN)
        {
            base = ((ElfLibrary*)this)->getBase();
        }

        const char* name = lib->getDynName() + base;
        Elf64_Rela* jmprel = (Elf64_Rela*)(lib->getDynValue(DT_JMPREL) + base);
        int jmprelcount = lib->getDynValue(DT_PLTRELSZ) / sizeof(Elf64_Rela);

        Elf64_Sym* symtab = (Elf64_Sym*)(lib->getDynValue(DT_SYMTAB) + base);
        const char* strtab = (const char*)(lib->getDynValue(DT_STRTAB) + base);

        for (i = 0; i < jmprelcount; i++)
        {
            relocateRela(lib->getLibrary(), &(jmprel[i]), base, symtab, strtab);
        }

        Elf64_Rela* rela = (Elf64_Rela*)(lib->getDynValue(DT_RELA) + base);
        int relacount = lib->getDynValue(DT_RELASZ) / sizeof(Elf64_Rela);

        for (i = 0; i < relacount; i++)
        {
            relocateRela(lib->getLibrary(), &(rela[i]), base, symtab, strtab);
        }

        if (lib->getLibrary() != this)
        {
            lib->getLibrary()->relocate();
        }

    }
    return true;
}

void ElfBinary::relocateRela(ElfLibrary* lib, Elf64_Rela* rela, uint64_t base, Elf64_Sym* symtab, const char* strtab)
{
    int sym = rela->r_info >> 32;
    int type = rela->r_info & 0xffffffff;

#ifdef DEBUG
    printf("ElfBinary::relocateRela: offset=%p, info=(sym=%d, type=%d), addend=0x%llx\n",
        rela->r_offset,
        sym,
        type,
        rela->r_addend);
#endif

    uint64_t* dest64 = (uint64_t*)(rela->r_offset + base);
    uint32_t* dest32 = (uint32_t*)(rela->r_offset + base);
    switch (type)
    {
        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        {
            int symType = symtab[sym].st_info & 0xf;
            int symBind = symtab[sym].st_info >> 4;
            const char* symName = strtab + symtab[sym].st_name;
#ifdef DEBUG
            printf(
                "ElfBinary::relocate: R_X86_64_JUMP_SLOT: sym name=%s, sym type=%d, bind=%d\n",
                symName,
                symType,
                symBind);
#endif
            Elf64_Sym* symbol = lib->findSymbol(symName);
#ifdef DEBUG
            printf(
                "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> symbol=%p\n",
                symbol);
#endif
            uint64_t value = 0;
            if (symbol != NULL)
            {
#ifdef DEBUG
                printf(
                    "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> symbol value=0x%llx\n",
                    symbol->st_value);
#endif
                if (symbol->st_value != 0)
                {
                    value = lib->getBase() + symbol->st_value;
                }
                else if (!strcmp(symName, "_rtld_global_ro"))
                {
                    value = (uint64_t)(&g_rtldGlobal);
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
                        "ElfBinary::relocate: R_X86_64_JUMP_SLOT:  -> _rtld_global_ro\n");
#endif
                }

            }
            if (type == R_X86_64_64)
            {
                value += rela->r_addend;
            }
            *dest64 = value;
        } break;

        case R_X86_64_RELATIVE:
        {
            *dest64 = (lib->getBase() + rela->r_addend);
        } break;

        case R_X86_64_TPOFF64:
        {
            *dest64 = m_tlsBase + rela->r_addend;
        } break;

        case R_X86_64_IRELATIVE:
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
        } break;

        default:
            printf("ElfBinary::relocate: Unhandled relocation type: %d\n", type);
            break;
    }

}

void ElfBinary::initTLS(void* tls, uint64_t tlsbase)
{
    m_tlsBase = tlsbase;

    int i;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(m_image + m_header->e_phoff);

    for (i = 0; i < m_header->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_TLS)
        {
            memcpy(
                tls,
                m_image + phdr[i].p_offset,
                phdr[i].p_filesz);
        }
    }
}

