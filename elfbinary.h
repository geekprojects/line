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

#ifndef __LINE_ELFBINARY_H_
#define __LINE_ELFBINARY_H_

#include "elf.h"

#include <vector>

#define ALIGN(_v, _a) (((_v) + _a - 1) & ~(_a - 1))

class ElfExec;
class ElfLibrary;
class LibraryEntry;

class ElfBinary
{
 protected:
    ElfExec* m_exec;

    char* m_path;
    char* m_image;
    Elf64_Ehdr* m_header;
    char* m_shStringTable;
    char* m_stringTable;

    std::vector<LibraryEntry*> m_libraries;
    uint64_t m_tlsBase;
    int m_tlsSize;

    Elf64_Shdr* findSection(const char* name);

    bool readDynamicHeader(Elf64_Phdr* header);

    void relocateRela(ElfLibrary* lib, Elf64_Rela* rela, uint64_t base, Elf64_Sym* symtab, const char* strtab);

 public:

    ElfBinary();
    virtual ~ElfBinary();

    bool load(const char* path);

    const char* getString(int name);
    Elf64_Sym* findSymbol(const char* sym);

    virtual bool map() = 0;

    bool loadLibraries();
    virtual bool relocate();

    char* getPath() { return m_path; }

    int getTLSSize() { return m_tlsSize; }
    void initTLS(void* tls, uint64_t tlsbase);
    uint64_t getTLSBase();
};

class Library : public ElfBinary
{
 protected:
    // Fields from the DYNAMIC header
    int m_dynNameIdx;
    const char* m_dynStrTab;

    uint64_t m_base;

 public:
    Library();
    virtual ~Library();

    void setDynNameIndex(int idx) { m_dynNameIdx = idx; }
    void setDynStrTab(const char* strtab) { m_dynStrTab = strtab; }
    const char* getDynName() { return m_dynStrTab + m_dynNameIdx; }
};

#endif
