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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>

#include "elfprocess.h"
#include "elflibrary.h"
#include "utils.h"

//#define DEBUG

using namespace std;

static ElfProcess* g_elfProcess = NULL;

uint64_t tls_get_addr()
{
    return g_elfProcess->getFS();
}

ElfProcess::ElfProcess(Line* line, ElfExec* exec)
{
    m_line = line;
    g_elfProcess = this;

    m_elf = exec;
    m_elf->setElfProcess(this);

    m_libraryLoadAddr = 0x40000000;
}

bool ElfProcess::start(int argc, char** argv)
{
    // Set up sigtrap handler
    struct sigaction act;
    memset (&act, 0, sizeof(act));
    act.sa_sigaction = ElfProcess::signalHandler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &act, 0);

    memset (&act, 0, sizeof(act));
    act.sa_sigaction = ElfProcess::signalHandler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, 0);

    // Set the environment
    char** environ = new char*[100];
    environ[0] = (char*)"HELLO=WORLD";
    environ[1] = (char*)"LC_CTYPE=C";
    environ[2] = NULL;

    // Set up brk pointer
    m_brk = m_elf->getEnd();

    // Set up TLS
    int tlssize = m_elf->getTLSSize() + 8;
    map<string, ElfLibrary*> libs = m_elf->getLibraries();
    map<string, ElfLibrary*>::iterator it;
    for (it = libs.begin(); it != libs.end(); it++)
    {
        int size = it->second->getTLSSize();
        tlssize += size;
    }

#ifdef DEBUG
    printf("ElfProcess::start: TLS: Total size: %d\n", tlssize);
#endif

    /*
     *    +---------+
     * -f |         | FS Base
     *    +---------+
     * -8 |         |
     *    +---------+
     * 0  | fs addr | FS Pointer
     *    +---------+
     */

    int tlspos = 0;//tlssize;
    for (it = libs.begin(); it != libs.end(); it++)
    {
        int size = it->second->getTLSSize();
        tlspos -= size;
#ifdef DEBUG
        printf("ElfProcess::start: TLS: %s: size=0x%x, pos=%d\n", it->first.c_str(), size, tlspos);
#endif
        it->second->setTLSBase(-tlspos);
    }

    m_fs = (uint64_t)malloc(tlssize + 1024);
    m_fsPtr = m_fs + tlssize;
#ifdef DEBUG
    printf("ElfProcess::start: TLS: FS: 0x%llx - 0x%llx\n", m_fs, m_fsPtr);
#endif

    m_elf->relocateLibraries();
    m_elf->relocate();

    tlspos = m_elf->getTLSSize();
    uint64_t tlsend = m_fsPtr - (tlspos + 0);
    for (it = libs.begin(); it != libs.end(); it++)
    {
        int size = it->second->getTLSSize();
        tlsend -= size;
        void* initpos = (void*)(tlsend /*- tlspos*/);
#ifdef DEBUG
        printf("ElfProcess::start: TLS: %s: init: initpos=%p\n", it->first.c_str(), initpos);
#endif
        it->second->initTLS(initpos);
    }

    writeFS64(0, m_fsPtr);

#ifdef DEBUG
    printf("ElfProcess::start: suspending...\n");
#endif

    // Tell the parent that we're ready!
    m_line->signal();

    // Wait for our parent to enable single step tracing etc
    task_suspend(mach_task_self());

    for (it = libs.begin(); it != libs.end(); it++)
    {
        if (it->first != "libpthread.so.0")
        {
            it->second->entry(argc, argv, environ);
        }
    }

    // Execute the ELF (Note, no Elves were harmed...)
    m_elf->entry(argc, argv, environ);

    return true;
}

void ElfProcess::signalHandler(int sig, siginfo_t* info, void* contextptr)
{
    ucontext_t* ucontext = (ucontext_t*)contextptr;

    if (sig == SIGTRAP)
    {
        g_elfProcess->trap(info, ucontext);
    }
    else
    {
        g_elfProcess->error(sig, info, ucontext);
    }
}

void ElfProcess::printregs(ucontext_t* ucontext)
{
    printf("rax=0x%08llx, rbx=0x%08llx, rcx=0x%08llx, rdx=0x%08llx\n",
        ucontext->uc_mcontext->__ss.__rax,
        ucontext->uc_mcontext->__ss.__rbx,
        ucontext->uc_mcontext->__ss.__rcx,
        ucontext->uc_mcontext->__ss.__rdx);
    printf("rdi=0x%08llx, rsi=0x%08llx, rbp=0x%08llx, rsp=0x%08llx\n",
        ucontext->uc_mcontext->__ss.__rdi,
        ucontext->uc_mcontext->__ss.__rsi,
        ucontext->uc_mcontext->__ss.__rbp,
        ucontext->uc_mcontext->__ss.__rsp);
    printf(" r8=0x%08llx,  r9=0x%08llx, r10=0x%08llx, r11=0x%08llx\n",
        ucontext->uc_mcontext->__ss.__r8,
        ucontext->uc_mcontext->__ss.__r9,
        ucontext->uc_mcontext->__ss.__r10,
        ucontext->uc_mcontext->__ss.__r11);
    printf("r12=0x%08llx, r13=0x%08llx, r14=0x%08llx, r15=0x%08llx\n",
        ucontext->uc_mcontext->__ss.__r12,
        ucontext->uc_mcontext->__ss.__r13,
        ucontext->uc_mcontext->__ss.__r14,
        ucontext->uc_mcontext->__ss.__r15);
    printf("rip=0x%08llx, rflags=0x%08llx\n",
        ucontext->uc_mcontext->__ss.__rip,
        ucontext->uc_mcontext->__ss.__rflags);
    printf(" cs=0x%08llx,  fs=0x%08llx,  gs=0x%08llx, m_fs=0x%08llx\n",
        ucontext->uc_mcontext->__ss.__cs,
        ucontext->uc_mcontext->__ss.__fs,
        ucontext->uc_mcontext->__ss.__gs,
        m_fs);
}

void ElfProcess::error(int sig, siginfo_t* info, ucontext_t* ucontext)
{
    printf(
        "ElfProcess::error: sig=%d, errno=%d, address=0x%llx\n",
        sig,
        info->si_errno,
        info->si_addr);
    printregs(ucontext);

    fflush(stdout);
    exit(1);
}

void ElfProcess::trap(siginfo_t* info, ucontext_t* ucontext)
{
    //x86_thread_state64_t*
#if 0
    if ((uint64_t)info->si_addr < 0x7fff90000000ull)
    {
        //printf("child_signal_handler: sig=%d, errno=%d, address=%p\n", sig, info->si_errno, info->si_addr);
        //printf("child_signal_handler:  -> RAX=0x%llx\n", ucontext->uc_mcontext->__ss.__rax);
    }

    if ((uint64_t)info->si_addr >= 0x433300 && (uint64_t)info->si_addr < 0x43350f)
    {
        printregs(ucontext);
    }
#endif
    if ((uint64_t)info->si_addr == 0x40dd52)
    {
        printregs(ucontext);
    }

    while (true)
    {
        uint8_t* addr = (uint8_t*)(ucontext->uc_mcontext->__ss.__rip);

        // Save ourselves a segfault
        if (addr == 0)
        {
            printf("ElfProcess::trap: addr=0x%llx\n", addr);
            printregs(ucontext);
            exit(1);
        }
        else if (
            ((uint64_t)addr >= 0x7bf00000 && (uint64_t)addr <= 0x7bffffff) ||
            ((uint64_t)addr >= 0x7fffc0000000))
        {
            // Line binary or kernel
#ifdef DEBUG
            printf("ElfProcess::trap: %p: line\n", addr);
#endif
            return;
        }

#ifdef DEBUG
        printf("ElfProcess::trap: %p: 0x%x 0x%x 0x%x\n", addr, *addr, *(addr + 1), *(addr + 2));
#endif
        if (*addr == 0x0f && *(addr + 1) == 0x05)
        {
            int syscall = ucontext->uc_mcontext->__ss.__rax;

#ifdef DEBUG
            printf("ElfProcess: trap: 0x%x: SYSCALL 0x%x\n", info->si_addr, syscall);
#endif

            execSyscall(syscall, ucontext);

            // Skip it!
            ucontext->uc_mcontext->__ss.__rip += 2;
        }
        else if (*addr == 0x64)
        {
            execFSInstruction(addr + 1, ucontext);
        }
        else
        {
            break;
        }

        // Better check that we don't need to handle the next instruction too
    }
}

