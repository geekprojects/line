#ifndef __LINE_H_
#define __LINE_H_

#include "elfexec.h"

class Line
{
 private:
    ElfExec m_elfBinary;

    pid_t m_elfPid;
 public:
    Line();
    ~Line();

    bool open(const char* elfpath);

    bool execute();

    ElfExec* getElfBinary() { return &m_elfBinary; }
};


#endif
