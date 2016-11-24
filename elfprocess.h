#ifndef __ELFPROCESS_H_
#define __ELFPROCESS_H_

#include <signal.h>

#include "elfexec.h"

class ElfProcess
{
 private:
    ElfExec* m_elf;

    uint64_t m_fs;
    uint64_t m_brk;

    uint8_t* m_rip;

    static void signalHandler(int sig, siginfo_t* info, void* contextptr);
    void trap(siginfo_t* info, ucontext_t* ucontext);
    void error(int sig, siginfo_t* info, ucontext_t* ucontext);

    void printregs(ucontext_t* ucontext);
    bool execSyscall(uint64_t syscall, ucontext_t* ucontext);
    bool execFSInstruction(uint8_t* rip, ucontext_t* ucontext);

    uint8_t fetch8();
    uint32_t fetch32();
    uint64_t fetchModRMAddress(int mod, int rm, int rexB, ucontext_t* ucontext);
    uint64_t fetchSIB(int rexB, ucontext_t* ucontext);
    uint64_t readRegister(int reg, int rexB, int size, ucontext_t* ucontext);
    void writeRegister(int reg, int rexB, int size, uint64_t value, ucontext_t* ucontext);

    uint64_t readFS64(int64_t offset)
    {
        uint64_t* ptr = (uint64_t*)((int64_t)m_fs + offset);
        return *ptr;
    }

    void writeFS32(int64_t offset, uint32_t value)
    {
        uint32_t* ptr = (uint32_t*)(m_fs + offset);
        *ptr = value;
    }

    void writeFS64(int64_t offset, uint64_t value)
    {
        uint64_t* ptr = (uint64_t*)((int64_t)m_fs + offset);
        *ptr = value;
    }

 public:
    ElfProcess(ElfExec* exec);
    ~ElfProcess();

    bool start();

    uint64_t getFS() { return m_fs; };
};


#endif
