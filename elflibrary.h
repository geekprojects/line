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

#ifndef __LINE_ELFLIBRARY_H_
#define __LINE_ELFLIBRARY_H_

#include "elfbinary.h"

#include <map>

class ElfExec;

class ElfLibrary : public ElfBinary
{
 protected:

    uint64_t m_base;

 public:
    ElfLibrary(ElfExec* exec);
    virtual ~ElfLibrary();

    virtual bool map();

    void setBase(uint64_t base) { m_base = base; }
    uint64_t getBase() { return m_base; }
/*
    void setDynNameIndex(int idx) { m_dynNameIdx = idx; }
    void setDynStrTab(const char* strtab) { m_dynStrTab = strtab; }
    const char* getDynName() { return m_dynStrTab + m_dynNameIdx; }
    void setDynRela(Elf64_Rela* rela) { m_dynRela = rela; }
    Elf64_Rela* getDynRela() { return m_dynRela; }
    void setDynRelaCount(int count) { m_dynRelaCount = count; }
    int getDynRelaCount() { return m_dynRelaCount; }
    void setDynJmpRel(Elf64_Rela* pltgot) { m_dynJmpRel = pltgot; }
    Elf64_Rela* getDynJmpRel() { return m_dynJmpRel; }
    void setDynPltRelSize(int count) { m_dynPltRelSize = count; }
    int getDynPltRelSize() { return m_dynPltRelSize; }
*/
};

class LibraryEntry
{
 protected:

    // Fields from the DYNAMIC header
    std::map<uint64_t, uint64_t> m_dyn;

    ElfLibrary* m_library;

 public:
    LibraryEntry() {}
    ~LibraryEntry() {}

    void setLibrary(ElfLibrary* lib) { m_library = lib; }
    ElfLibrary* getLibrary() { return m_library; }

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

    const char* getDynName() {return (const char*)(getDynValue(DT_STRTAB) + getDynValue(DT_NEEDED)); }

    bool init();
};

#endif
