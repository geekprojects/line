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
#include <map>

#define ALIGN(_v, _a) (((_v) + _a - 1) & ~(_a - 1))

class ElfExec;
class ElfLibrary;
class LibraryEntry;
class LineProcess;
class ElfBinary;

struct IFuncRela
{
    Elf64_Rela* rela;
    Elf64_Sym* symbol;
    ElfBinary* lib;
};

class ElfBinary
{
 protected:
    LineProcess* m_process;
    ElfExec* m_exec;

    char* m_path;
    char* m_image;
    Elf64_Ehdr* m_header;
    char* m_shStringTable;
    char* m_stringTable;
    uint64_t m_end;
    uint64_t m_base;

    std::map<std::string, Elf64_Sym*> m_symbols;
    std::vector<IFuncRela> m_ifuncRelas;

    Elf64_Shdr* m_symbolSection;

    int m_tlsBase;
    int m_tlsSize;

    std::vector<uint64_t> m_needed;
    std::map<uint64_t, uint64_t> m_dyn;
    
    Elf64_Shdr* findSection(const char* name);

    bool readDynamicHeader(Elf64_Phdr* header);

    bool mapStatic();
    bool mapDynamic();

    void relocateRela(Elf64_Rela* rela, uint64_t base, Elf64_Sym* symtab, const char* strtab);

 public:

    ElfBinary();
    virtual ~ElfBinary();

    bool load(const char* path);

    const char* getString(int name);
    Elf64_Sym* findSymbol(const char* sym);

    bool map();
    uint64_t getEnd() { return m_end; }

    void setBase(uint64_t base) { m_base = base; }
    uint64_t getBase() { return m_base; }

    bool loadLibraries();
    virtual bool relocate();
    bool relocateIFuncs();

    void setProcess(LineProcess* process) { m_process = process; }
    char* getPath() { return m_path; }

    int getTLSSize() { return m_tlsSize; }
    void setTLSBase(int tlsbase) { m_tlsBase = tlsbase; }
    void initTLS(void* tls);
    uint64_t getTLSBase();

    void setDynValue(uint64_t tag, uint64_t value) { m_dyn.insert(std::make_pair(tag, value)); }
    uint64_t getDynValue(uint64_t tag)
    {
        std::map<uint64_t, uint64_t>::iterator it;
        it = m_dyn.find(tag);
        if (it != m_dyn.end())
        {
            return it->second;
        }
        return 0;
    }
};

#endif
