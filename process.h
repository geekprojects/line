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

#include <libdis.h>

#include "line.h"
#include "elfexec.h"
#include "kernel.h"
#include "mainthread.h"
#include "glibcruntime.h"
#include "patcher.h"
#include "logger.h"

#include <deque>

class LinuxKernel;
class LinuxProcess;

enum ProcessRequestType
{
    REQUEST_SINGLESTEP
};

struct ProcessRequest
{
    ProcessRequestType type;
    LineThread* thread;
    //ProcessRequest() { type = REQUEST_NONE; }
};

struct ProcessRequestSingleStep : public ProcessRequest
{
    bool enable;
};

class LineProcess : private Logger
{
 private:
    ElfExec* m_elf;
    Line* m_line;
    Patcher m_patcher;

    std::map<pthread_t, LineThread*> m_threads;
    MainThread* m_mainThread;

    pthread_cond_t m_requestCond;
    pthread_mutex_t m_requestCondMutex;
    pthread_mutex_t m_requestMutex;
    std::deque<ProcessRequest*> m_requests;

    uint64_t m_fs;
    uint64_t m_fsPtr;
    uint64_t m_brk;
    uint64_t m_libraryLoadAddr;

    uint8_t* m_rip;

    LinuxKernel m_kernel;
    GlibcRuntime m_glibcRuntime;

    static void signalHandler(int sig, siginfo_t* info, void* contextptr);
    void trap(siginfo_t* info, ucontext_t* ucontext);
    void error(int sig, siginfo_t* info, ucontext_t* ucontext);

    bool execFSInstruction(uint8_t* rip, uint8_t firstByte, ucontext_t* ucontext);

    uint8_t fetch8();
    uint32_t fetch32();
    uint64_t fetchModRMAddress(int mod, int rm, int rexB, ucontext_t* ucontext);
    uint64_t fetchSIB(int rexB, ucontext_t* ucontext);
    uint64_t readRegister(int reg, int rexB, int size, ucontext_t* ucontext);
    void writeRegister(int reg, int rexB, int size, uint64_t value, ucontext_t* ucontext);

    uint64_t getRegister(x86_reg_t reg, ucontext_t* ucontext);

    uint64_t readFS64(int64_t offset)
    {
        uint64_t* ptr = (uint64_t*)((int64_t)m_fsPtr + offset);
#ifdef DEBUG_FS
printf("LineProcess::readFS64: offset=%lld, m_fsPtr=0x%llx -> %p\n", offset, m_fsPtr, ptr);
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
        printf("LineProcess::writeFS64: offset=%lld, m_fsPtr=0x%llx -> %p = 0x%llx\n", offset, m_fsPtr, ptr, value);
#endif
        *ptr = value;
    }

 public:
    LineProcess(Line* line, ElfExec* exec);
    ~LineProcess();

    Line* getLine() { return m_line; }
    ElfExec* getExec() { return m_elf; }
    LinuxKernel* getKernel() { return &m_kernel; }
    GlibcRuntime* getRuntime() { return &m_glibcRuntime; }
    Patcher* getPatcher() { return &m_patcher; }

    void addThread(LineThread* thread);
    LineThread* getCurrentThread();

    bool init();
    bool start(int argc, char** argv);
    bool requestLoop();

    uint64_t getFS() { return m_fs; };
    uint64_t getFSPtr()
    {
        return m_fsPtr;
    }

    void setFS(uint64_t fs, uint64_t size)
    {
        m_fs = fs;
        m_fsPtr = m_fs + size;
    }

    uint64_t getBrk() { return m_brk; }
    void setBrk(uint64_t brk) { m_brk = brk; }

    uint64_t getNextLibraryLoadAddr()
    {
        uint64_t addr = m_libraryLoadAddr;
        m_libraryLoadAddr += 0x1000000;
        return addr;
    }

    bool request(ProcessRequest* request);
    bool requestSingleStep(LineThread* thread, bool enable);
    void checkSingleStep();
    void setSingleStep(LineThread* thread, bool enable);

    void printregs(ucontext_t* ucontext);

    static LineProcess* getProcess();
};


#endif
