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

class ElfProcess
{
 private:
    Line* m_line;

    uint64_t m_fs;
    uint64_t m_brk;

    static void signalHandler(int sig, siginfo_t* info, void* contextptr);
    void trap(siginfo_t* info, ucontext_t* ucontext);
    void error(int sig, siginfo_t* info, ucontext_t* ucontext);

    bool execSyscall();

 public:
    ElfProcess(Line* line);
    ~ElfProcess();

    bool start();
};


#endif
