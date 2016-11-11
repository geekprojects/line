#ifndef __LINE_H_
#define __LINE_H_

#include "elfbinary.h"

class Line
{
 private:
    ElfBinary m_elfBinary;

    pid_t m_elfPid;
 public:
    Line();
    ~Line();

    bool open(const char* elfpath);

    bool execute();

    ElfBinary* getElfBinary() { return &m_elfBinary; }
};


#endif
