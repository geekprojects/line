#ifndef __LINE_ELFEXEC_H_
#define __LINE_ELFEXEC_H_

#include "elfbinary.h"

#include <string>
#include <vector>
#include <map>

#define ALIGN(_v, _a) (((_v) + _a - 1) & ~(_a - 1))

class ElfLibrary;
class LibraryEntry;

class ElfExec : public ElfBinary
{
 protected:
    std::map<std::string, ElfLibrary*> m_libraries;

 public:

    ElfExec();
    virtual ~ElfExec();

    virtual bool map();

    void addLibrary(std::string name, ElfLibrary* library);
    ElfLibrary* getLibrary(std::string name);
    std::map<std::string, ElfLibrary*>& getLibraries() { return m_libraries; };

    void entry(int argc, char** argv, char** envp);
};

#endif
