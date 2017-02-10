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

#ifndef __ELFPROCESS_H_
#define __ELFPROCESS_H_

#include <signal.h>
#include <dirent.h>

#include "line.h"
#include "elfexec.h"
#include "filesystem.h"

struct LinuxSocket
{
    int fd;
    int family;
    int type;
    int protocol;
};

class ElfProcess
{
 private:
    Line* m_line;
    ElfExec* m_elf;

    uint64_t m_fs;
    uint64_t m_fsPtr;
    uint64_t m_brk;
    uint64_t m_libraryLoadAddr;

    uint8_t* m_rip;

    FileSystem m_fileSystem;
    std::map<int, LinuxSocket*> m_sockets;
    std::map<int, DIR*> m_dirs;

    static void signalHandler(int sig, siginfo_t* info, void* contextptr);
    void trap(siginfo_t* info, ucontext_t* ucontext);
    void error(int sig, siginfo_t* info, ucontext_t* ucontext);

    void printregs(ucontext_t* ucontext);
    bool execSyscall(uint64_t syscall, ucontext_t* ucontext);
    bool execFSInstruction(uint8_t* rip, ucontext_t* ucontext);

    void syscallErrnoResult(ucontext_t* ucontext, uint64_t res, bool success, int err);

    uint8_t fetch8();
    uint32_t fetch32();
    uint64_t fetchModRMAddress(int mod, int rm, int rexB, ucontext_t* ucontext);
    uint64_t fetchSIB(int rexB, ucontext_t* ucontext);
    uint64_t readRegister(int reg, int rexB, int size, ucontext_t* ucontext);
    void writeRegister(int reg, int rexB, int size, uint64_t value, ucontext_t* ucontext);

    uint64_t readFS64(int64_t offset)
    {
        uint64_t* ptr = (uint64_t*)((int64_t)m_fsPtr + offset);
#ifdef DEBUG_FS
printf("ElfProcess::readFS64: offset=%d, m_fsPtr=0x%llx -> %p\n", offset, m_fsPtr, ptr);
#endif
        return *ptr;
    }

    void writeFS32(int64_t offset, uint32_t value)
    {
        uint32_t* ptr = (uint32_t*)(m_fsPtr + offset);
        *ptr = value;
    }

    void writeFS64(int64_t offset, uint64_t value)
    {
        uint64_t* ptr = (uint64_t*)((int64_t)m_fsPtr + offset);
#ifdef DEBUG_FS
        printf("ElfProcess::writeS64: offset=%d, m_fsPtr=0x%llx -> %p = 0x%llx\n", offset, m_fsPtr, ptr, value);
#endif
        *ptr = value;
    }

 public:
    ElfProcess(Line* line, ElfExec* exec);
    ~ElfProcess();

    bool start(int argc, char** argv);

    uint64_t getFS() { return m_fs; };
    uint64_t getFSPtr()
    {
        return m_fsPtr;
    }

    uint64_t getNextLibraryLoadAddr()
    {
        uint64_t addr = m_libraryLoadAddr;
        m_libraryLoadAddr += 0x1000000;
        return addr;
    }

    void log(const char* __format, ...);
};


#endif
