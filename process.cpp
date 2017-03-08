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
//#define DEBUG_TLS

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

    init();
}

bool LineProcess::init()
{
    pthread_cond_init(&m_requestCond, NULL);
    pthread_mutex_init(&m_requestCondMutex, NULL);
    pthread_mutex_init(&m_requestMutex, NULL);

    return true;
}

bool LineProcess::start(int argc, char** argv)
{
    // Set up sigtrap handler
    struct sigaction act;
    memset (&act, 0, sizeof(act));
    act.sa_sigaction = LineProcess::signalHandler;
    act.sa_flags = SA_SIGINFO;
    //sigemptyset(&act.sa_mask);
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
    int tlssize = m_elf->getTLSSize();// + sizeof(struct linux_pthread);
    map<string, ElfLibrary*> libs = m_elf->getLibraries();
    map<string, ElfLibrary*>::iterator it;
    for (it = libs.begin(); it != libs.end(); it++)
    {
        int size = it->second->getTLSSize();
        tlssize += size;
    }

#ifdef DEBUG_TLS
    printf("LineProcess::start: TLS: Total size: %d\n", tlssize);
#endif

    /*
     *   0  +----------+  -144 exec base
     *      | Exec TLS |
     *  16  +----------+  -128 libc base
     *      | libc TLS |
     * 128  +----------+    -0 libm base
     *      | libm TLS |
     * 128  +----------+    -0 <-- FS Pointer
     *  
     */

    int tlspos = 0;
    map<string, ElfLibrary*>::reverse_iterator rit;
    for (rit = libs.rbegin(); rit != libs.rend(); rit++)
    {
        int size = rit->second->getTLSSize();
        tlspos += size;
        rit->second->setTLSBase(-tlspos);
#ifdef DEBUG_TLS
        printf("LineProcess::start: TLS: %s: size=0x%x, pos=%d\n", rit->first.c_str(), size, -tlspos);
#endif
    }

    int size = m_elf->getTLSSize();
tlspos += size;
#ifdef DEBUG_TLS
    printf("LineProcess::start: TLS: %s: size=0x%x, base=%d\n", m_elf->getPath(), size, -tlspos);
#endif
    m_elf->setTLSBase(-tlspos);

    m_fs = (uint64_t)malloc(tlssize + sizeof(struct linux_pthread));
    m_fsPtr = m_fs + tlssize;
#ifdef DEBUG_TLS
    printf("LineProcess::start: TLS: FS: 0x%llx - 0x%llx\n", m_fs, m_fsPtr);
#endif

    m_elf->relocateLibraries();
    m_elf->relocate();

    tlspos = m_elf->getTLSSize();

    void* initpos = (void*)((int64_t)m_fsPtr + m_elf->getTLSBase());
    printf(
        "LineProcess::start: TLS: %s: init: %d: %p-0x%llx, size=%d\n",
        m_elf->getPath(),
        m_elf->getTLSBase(),
        initpos,
        (uint64_t)initpos + m_elf->getTLSSize(),
        m_elf->getTLSSize());
    m_elf->initTLS(initpos);

    for (it = libs.begin(); it != libs.end(); it++)
    {
        void* initpos = (void*)((int64_t)m_fsPtr + it->second->getTLSBase());
#ifdef DEBUG_TLS
        int size = it->second->getTLSSize();
        printf(
            "LineProcess::start: TLS: %s: %d: init: %p-0x%llx, size=%d\n", it->first.c_str(), it->second->getTLSBase(), initpos, (uint64_t)initpos + size, size);
#endif
        it->second->initTLS(initpos);
    }

    // Set up the initial pthread
    struct linux_pthread* pthread = (struct linux_pthread*)m_fsPtr;
    //*((uint64_t*)(m_fsPtr + 0x00)) = (uint64_t)pthread;
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

    return requestLoop();
}

bool LineProcess::requestLoop()
{
    while (true)
    {
        pthread_cond_wait(&m_requestCond, &m_requestCondMutex);

        ProcessRequest* request;
        bool hasRequest = false;
        pthread_mutex_lock(&m_requestMutex);
        if (!m_requests.empty())
        {
            request = m_requests.front();
            hasRequest = true;
            m_requests.pop_front();
        }
        pthread_mutex_unlock(&m_requestMutex);
#ifdef DEBUG
        printf("LineProcess::start: request: %p\n", request);
#endif
        if (hasRequest)
        {
            switch (request->type)
            {
                case REQUEST_SINGLESTEP:
                {
                    ProcessRequestSingleStep* singleStep = (ProcessRequestSingleStep*)request;
                    setSingleStep(singleStep->thread, singleStep->enable);
                } break;
            }
            request->thread->signalFromProcess();
            delete request;
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
            ((uint64_t)addr >= 0x7fff00000000))
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

void LineProcess::setSingleStep(LineThread* thread, bool enable)
{
    int res;

    // Get ELF Thread port
    task_t port = thread->getTask();

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
    if (enable)
    {
        gp_regs.uts.ts64.__rflags |= X86_EFLAGS_T;
    }
    else
    {
        gp_regs.uts.ts64.__rflags &= ~X86_EFLAGS_T;
    }

    res = thread_set_state(
        port,
        x86_THREAD_STATE,
        (thread_state_t) &gp_regs,
        gp_count);

    if (res != 0)
    {
        int err = errno;
        printf("Line::execute: Failed to set thread state: res=%d, err=%d\n", res, err);
        exit(1);
    }
}

void LineProcess::checkSingleStep()
{
    task_t port = mach_thread_self();

    /*
     * Set the Trace flag on the child
     */

    // Get current state
    x86_thread_state_t gp_regs;
    unsigned int gp_count = x86_THREAD_STATE_COUNT;
    int res = thread_get_state(port, x86_THREAD_STATE, (thread_state_t)&gp_regs, &gp_count);
    if (res != 0)
    {
        int err = errno;
        printf("Line::execute: Failed to get thread state: res=%d, err=%d\n", res, err);
        exit(1);
    }
    printf("checkSingleStep: rflags=0x%llx, T=%d\n", gp_regs.uts.ts64.__rflags, !!(gp_regs.uts.ts64.__rflags & X86_EFLAGS_T));
}

bool LineProcess::request(ProcessRequest* request)
{
#ifdef DEBUG
    printf("LineProcess::requestSingleStep: Adding request...\n");
#endif

    // Add the request to the queue
    pthread_mutex_lock(&m_requestMutex);
    m_requests.push_back(request);
    pthread_mutex_unlock(&m_requestMutex);

    // Tell the request thread that there's a request waiting
    pthread_cond_signal(&m_requestCond);

    // Wait for the request to be handled
    request->thread->waitForProcess();

    return true;
}

bool LineProcess::requestSingleStep(LineThread* thread, bool enable)
{
    ProcessRequestSingleStep* req = new ProcessRequestSingleStep();
    req->type = REQUEST_SINGLESTEP;
    req->thread = thread;
    req->enable = enable;

    return request(req);
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

