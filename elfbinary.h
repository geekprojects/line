#ifndef __LINE_ELFBINARY_H_
#define __LINE_ELFBINARY_H_

#include "elf.h"

#define ALIGN(_v, _a) (((_v) + _a - 1) & ~(_a - 1))

class ElfBinary
{
 private:

    char* m_image;
    Elf64_Ehdr* m_header;
    char* m_shStringTable;
    char* m_stringTable;

    Elf64_Shdr* findSection(const char* name);

 public:

    ElfBinary();
    ~ElfBinary();

    bool load(const char* path);
    Elf64_Sym* findSymbol(const char* sym);

    bool map();

    bool entry(int argc, char** argv, char** envp);
};

#endif
