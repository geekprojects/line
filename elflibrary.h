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
