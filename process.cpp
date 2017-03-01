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

#include "process.h"
#include "elflibrary.h"
#include "kernel.h"
#include "utils.h"
#include "tls.h"

//#define DEBUG

#define X86_EFLAGS_T 0x100UL

using namespace std;

static LineProcess* g_elfProcess = NULL;

extern char **environ;

uint64_t tls_get_addr()
{
    return g_elfProcess->getFSPtr();
}

LineProcess::LineProcess(Line* line, ElfExec* exec)
{
    m_line = line;
    g_elfProcess = this;

    m_elf = exec;
    m_elf->setProcess(this);

    m_kernel = new LinuxKernel(this);

    m_libraryLoadAddr = 0x40000000;

    pthread_cond_init(&m_requestCond, NULL);
    pthread_mutex_init(&m_requestCondMutex, NULL);
    pthread_mutex_init(&m_requestMutex, NULL);
}

bool LineProcess::start(int argc, char** argv)
{
    // Set up sigtrap handler
    struct sigaction act;
    memset (&act, 0, sizeof(act));
    act.sa_sigaction = LineProcess::signalHandler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &act, 0);

    memset (&act, 0, sizeof(act));
    act.sa_sigaction = LineProcess::signalHandler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, 0);

    // Set the environment
    int envsize = 0;
    while (environ[envsize] != NULL)
    {
        envsize++;
    }
    char** linux_environ = new char*[envsize + 2];

    int i;
    for (i = 0; i < envsize; i++)
    {
        const char* env = environ[i];
        if (!strncmp("PATH=", env, 5))
        {
            linux_environ[i] = (char*)"PATH=/bin:/usr/bin";
        }
        else
        {
            linux_environ[i] = environ[i];
        }
    }
    linux_environ[envsize] = (char*)"LINUX_ON_MAC=1";
    linux_environ[envsize + 1] = NULL;

    // Set up brk pointer
    m_brk = m_elf->getEnd();

    // Set up TLS
    int tlssize = m_elf->getTLSSize() + sizeof(struct pthread);
    map<string, ElfLibrary*> libs = m_elf->getLibraries();
    map<string, ElfLibrary*>::iterator it;
    for (it = libs.begin(); it != libs.end(); it++)
    {
        int size = it->second->getTLSSize();
        tlssize += size;
    }

#ifdef DEBUG
    printf("LineProcess::start: TLS: Total size: %d\n", tlssize);
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
        printf("LineProcess::start: TLS: %s: size=0x%x, pos=%d\n", it->first.c_str(), size, tlspos);
#endif
        it->second->setTLSBase(-tlspos);
    }

    m_fs = (uint64_t)malloc(tlssize + 1024);
    m_fsPtr = m_fs + tlssize;
#ifdef DEBUG
    printf("LineProcess::start: TLS: FS: 0x%llx - 0x%llx\n", m_fs, m_fsPtr);
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
        printf("LineProcess::start: TLS: %s: init: initpos=%p\n", it->first.c_str(), initpos);
#endif
        it->second->initTLS(initpos);
    }

    // Set up the initial pthread
    struct pthread* pthread = (struct pthread*)m_fsPtr;
    *((uint64_t*)(m_fsPtr + 0x10)) = (uint64_t)pthread;
    pthread->pid = getpid();
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);
    pthread->tid = tid;

#ifdef DEBUG
    printf("LineProcess::start: pthread pid=%p\n", &(pthread->pid));
    printf("LineProcess::start: pthread tid=%p\n", &(pthread->tid));
#endif

    writeFS64(0, m_fsPtr);

#ifdef DEBUG
    printf("LineProcess::start: Starting main thread...\n");
#endif

    m_mainThread = new MainThread(this);
    m_mainThread->start(argc, argv);

    printf("LineProcess::start: Starting request loop\n");
    while (true)
    {
        printf("LineProcess::start: Waiting for request...\n");
        pthread_cond_wait(&m_requestCond, &m_requestCondMutex);
        printf("LineProcess::start: Woken up!\n");

        LineThread* request = NULL;
        pthread_mutex_lock(&m_requestMutex);
        if (!m_requests.empty())
        {
            request = m_requests.front();
            m_requests.pop_front();
        }
        pthread_mutex_unlock(&m_requestMutex);
        printf("LineProcess::start: request: %p\n", request);
        if (request != NULL)
        {
            setSingleStep(request);
            request->signalFromProcess();
        }
    }

    return true;
}

void LineProcess::addThread(LineThread* thread)
{
    m_threads.insert(make_pair(thread->getPThread(), thread));
}

void LineProcess::signalHandler(int sig, siginfo_t* info, void* contextptr)
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

void LineProcess::printregs(ucontext_t* ucontext)
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

void LineProcess::error(int sig, siginfo_t* info, ucontext_t* ucontext)
{
    log(
        "error: sig=%d, errno=%d, address=%p\n",
        sig,
        info->si_errno,
        info->si_addr);
    printregs(ucontext);

    fflush(stdout);
    exit(1);
}

void LineProcess::trap(siginfo_t* info, ucontext_t* ucontext)
{
    while (true)
    {
        uint8_t* addr = (uint8_t*)(ucontext->uc_mcontext->__ss.__rip);

        // Save ourselves a segfault
        if (addr == 0)
        {
            log("trap: addr=%p", addr);
            printregs(ucontext);
            exit(1);
        }
        else if (
            ((uint64_t)addr >= IMAGE_BASE && (uint64_t)addr <= (IMAGE_BASE + 0xffffff)) ||
            ((uint64_t)addr >= 0x7fffc0000000))
        {
            // Line binary or kernel
#ifdef DEBUG_OSX
            printf("LineProcess::trap: %p: line\n", addr);
#endif
            return;
        }

        if (m_line->getConfigTrace())
        {
            log("trap: %p: 0x%x 0x%x 0x%x", addr, *addr, *(addr + 1), *(addr + 2));
        }

        if (*addr == 0x0f && *(addr + 1) == 0x05)
        {
            int syscall = ucontext->uc_mcontext->__ss.__rax;

#ifdef DEBUG
            log("trap: %p: SYSCALL 0x%x", info->si_addr, syscall);
#endif

            m_kernel->syscall(syscall, ucontext);

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

LineThread* LineProcess::getCurrentThread()
{
    pthread_t self = pthread_self();
    map<pthread_t, LineThread*>::iterator it;
it = m_threads.find(self);
if (it != m_threads.end())
{
return it->second;
}
return NULL;
}

void LineProcess::setSingleStep(LineThread* thread)
{
    int res;

    // Get ELF Thread port
    task_t port = pthread_mach_thread_np(thread->getPThread());

    /*
     * Set the Trace flag on the child
     */

    // Get current state
    x86_thread_state_t gp_regs;
    unsigned int gp_count = x86_THREAD_STATE_COUNT;
    res = thread_get_state(port, x86_THREAD_STATE, (thread_state_t)&gp_regs, &gp_count);
    if (res != 0)
    {
        int err = errno;
        printf("Line::execute: Failed to get thread state: res=%d, err=%d\n", res, err);
        exit(1);
    }

    // Set Single Step flags in eflags
    gp_regs.uts.ts64.__rflags = (gp_regs.uts.ts64.__rflags & ~X86_EFLAGS_T) | X86_EFLAGS_T;
    res = thread_set_state(
        port,
        x86_THREAD_STATE,
        (thread_state_t) &gp_regs,
        gp_count);
}

bool LineProcess::requestSingleStep(LineThread* thread)
{
printf("LineProcess::requestSingleStep: Adding request...\n");
    // Add the request to the queue
    pthread_mutex_lock(&m_requestMutex);
    m_requests.push_back(thread);
    pthread_mutex_unlock(&m_requestMutex);

printf("LineProcess::requestSingleStep: Signaling process...\n");
    // Tell the request thread that there's a request waiting
    pthread_cond_signal(&m_requestCond);

printf("LineProcess::requestSingleStep: Waiting for response...\n");
    // Wait for the request to be handled
    thread->waitForProcess();

printf("LineProcess::requestSingleStep: Done!\n");

    return true;
}

void LineProcess::log(const char* format, ...)
{
    va_list va;
    va_start(va, format);

    char buf[4096];
    vsnprintf(buf, 4096, format, va);
    char timeStr[256];
    time_t t;
    struct tm *tm;
    t = time(NULL);
    tm = localtime(&t);
    strftime(timeStr, 256, "%Y/%m/%d %H:%M:%S", tm);

    pid_t pid = getpid();

    printf("%s: %d: %s\n", timeStr, pid, buf);
}
