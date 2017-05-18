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

#include <libdis.h>

#include "process.h"
#include "elflibrary.h"
#include "kernel.h"
#include "utils.h"
#include "tls.h"

//#define DEBUG
//#define DEBUG_TLS
#define DEBUG_PATCH

#define X86_EFLAGS_T 0x100UL

using namespace std;

static LineProcess* g_process = NULL;

extern char **environ;

LineProcess::LineProcess(Line* line, ElfExec* exec)
    : Logger("Process"), m_elf(exec), m_patcher(this), m_kernel(this)
{
    m_line = line;
    g_process = this;

    m_libraryLoadAddr = 0x40000000;

    x86_init(opt_64_bit, NULL, NULL);

    init();
}

LineProcess::~LineProcess()
{
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

    memset (&act, 0, sizeof(act));
    act.sa_sigaction = LineProcess::signalHandler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &act, 0);

    // Set the environment
    int envsize = 0;
    while (environ[envsize] != NULL)
    {
        envsize++;
    }
    char** linux_environ = (char**)malloc(envsize + 2);

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
    log("start: TLS: Total size: %d", tlssize);
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
        log("start: TLS: %s: size=0x%x, pos=%d", rit->first.c_str(), size, -tlspos);
#endif
    }

    int size = m_elf->getTLSSize();
    tlspos += size;

#ifdef DEBUG_TLS
    log("start: TLS: %s: size=0x%x, base=%d", m_elf->getPath(), size, -tlspos);
#endif
    m_elf->setTLSBase(-tlspos);

    m_fs = (uint64_t)malloc(tlssize + sizeof(struct linux_pthread));
    m_fsPtr = m_fs + tlssize;
#ifdef DEBUG_TLS
    log("start: TLS: FS: 0x%llx - 0x%llx", m_fs, m_fsPtr);
#endif

    m_elf->relocateLibraries();
    m_elf->relocate();

    tlspos = m_elf->getTLSSize();

    void* initpos = (void*)((int64_t)m_fsPtr + m_elf->getTLSBase());
#ifdef DEBUG_TLS
    log(
        "start: TLS: %s: init: %d: %p-0x%llx, size=%d",
        m_elf->getPath(),
        m_elf->getTLSBase(),
        initpos,
        (uint64_t)initpos + m_elf->getTLSSize(),
        m_elf->getTLSSize());
#endif
    m_elf->initTLS(initpos);

    for (it = libs.begin(); it != libs.end(); it++)
    {
        void* initpos = (void*)((int64_t)m_fsPtr + it->second->getTLSBase());
#ifdef DEBUG_TLS
        int size = it->second->getTLSSize();
        log(
            "start: TLS: %s: %d: init: %p-0x%llx, size=%d",
            it->first.c_str(),
            it->second->getTLSBase(),
            initpos,
            (uint64_t)initpos + size,
            size);
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
    log("start: pthread pid=%p", &(pthread->pid));
    log("start: pthread tid=%p", &(pthread->tid));
#endif

    writeFS64(0, m_fsPtr);

#ifdef DEBUG
    log("start: Starting main thread...");
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
        log("start: request: %p", request);
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
            // XXX TODO: delete request;
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
        g_process->trap(info, ucontext);
    }
    else
    {
        g_process->error(sig, info, ucontext);
    }
}

void LineProcess::printregs(ucontext_t* ucontext)
{
    log("rax=0x%08llx, rbx=0x%08llx, rcx=0x%08llx, rdx=0x%08llx",
        ucontext->uc_mcontext->__ss.__rax,
        ucontext->uc_mcontext->__ss.__rbx,
        ucontext->uc_mcontext->__ss.__rcx,
        ucontext->uc_mcontext->__ss.__rdx);
    log("rdi=0x%08llx, rsi=0x%08llx, rbp=0x%08llx, rsp=0x%08llx",
        ucontext->uc_mcontext->__ss.__rdi,
        ucontext->uc_mcontext->__ss.__rsi,
        ucontext->uc_mcontext->__ss.__rbp,
        ucontext->uc_mcontext->__ss.__rsp);
    log(" r8=0x%08llx,  r9=0x%08llx, r10=0x%08llx, r11=0x%08llx",
        ucontext->uc_mcontext->__ss.__r8,
        ucontext->uc_mcontext->__ss.__r9,
        ucontext->uc_mcontext->__ss.__r10,
        ucontext->uc_mcontext->__ss.__r11);
    log("r12=0x%08llx, r13=0x%08llx, r14=0x%08llx, r15=0x%08llx",
        ucontext->uc_mcontext->__ss.__r12,
        ucontext->uc_mcontext->__ss.__r13,
        ucontext->uc_mcontext->__ss.__r14,
        ucontext->uc_mcontext->__ss.__r15);
    log("rip=0x%08llx, rflags=0x%08llx",
        ucontext->uc_mcontext->__ss.__rip,
        ucontext->uc_mcontext->__ss.__rflags);
    log(" cs=0x%08llx,  fs=0x%08llx,  gs=0x%08llx, m_fs=0x%08llx",
        ucontext->uc_mcontext->__ss.__cs,
        ucontext->uc_mcontext->__ss.__fs,
        ucontext->uc_mcontext->__ss.__gs,
        m_fs);
}

void LineProcess::error(int sig, siginfo_t* info, ucontext_t* ucontext)
{
    log(
        "error: sig=%d, errno=%d, address=%p",
        sig,
        info->si_errno,
        info->si_addr);
    printregs(ucontext);

    uint64_t rip = ucontext->uc_mcontext->__ss.__rip;
    if (rip < IMAGE_BASE && !m_patcher.isPatched(rip))
    {
        // HACK HACK HACK
        log("Failed in unpatched code! ATTEMPTING TO PATCH, THIS MIGHT FAIL");
        m_patcher.patch(ucontext->uc_mcontext->__ss.__rip);
        return;
    }

    exit(1);
}

uint64_t LineProcess::getRegister(x86_reg_t reg, ucontext_t* ucontext)
{
    switch (reg.id)
    {
        case 0: return 0;
        case 1: return ucontext->uc_mcontext->__ss.__rax;
        case 2: return ucontext->uc_mcontext->__ss.__rcx;
        case 3: return ucontext->uc_mcontext->__ss.__rdx;
        case 4: return ucontext->uc_mcontext->__ss.__rbx;
        case 5: return ucontext->uc_mcontext->__ss.__rsp;
        case 6: return ucontext->uc_mcontext->__ss.__rbp;
        case 7: return ucontext->uc_mcontext->__ss.__rsi;
        case 8: return ucontext->uc_mcontext->__ss.__rdi;
        case 97: return ucontext->uc_mcontext->__ss.__r8;
        case 98: return ucontext->uc_mcontext->__ss.__r9;
        case 99: return ucontext->uc_mcontext->__ss.__r10;
        case 100: return ucontext->uc_mcontext->__ss.__r11;
        case 101: return ucontext->uc_mcontext->__ss.__r12;
        case 102: return ucontext->uc_mcontext->__ss.__r13;
        case 103: return ucontext->uc_mcontext->__ss.__r14;
        case 104: return ucontext->uc_mcontext->__ss.__r15;
        default:
            //log("patchCode: 0x%llx: %s: Unhandled register: %d", patchedAddr, insntype, target->data.reg.id);
            log("getregister: Unhandled register: %s, id=%d", reg.name, reg.id);
            exit(255);
            break;
    }
}

void LineProcess::trap(siginfo_t* info, ucontext_t* ucontext)
{
    uint8_t* addr = (uint8_t*)(ucontext->uc_mcontext->__ss.__rip);
    //log("trap: %p: Trapped!", addr);
    if (addr[-1] != 0xcc)
    {
        log("trap: %p: ERROR: Trap in non patched code");
        exit(255);
    }

    uint64_t patchedAddr = ucontext->uc_mcontext->__ss.__rip - 1;
    Patch* patch = m_patcher.getPatch(patchedAddr);

    switch (patch->type)
    {
        case PATCH_CALL:
        {
            const char* insntype;
            if (patch->insn.type == insn_jmp || patch->insn.type == insn_jcc)
            {
                insntype = "BRANCH";
            }
            else
            {
                insntype = "CALL";
            }

            x86_op_t* target = x86_get_branch_target(&(patch->insn));
            if (target->datatype == op_byte )
            {
                log("trap: 0x%llx: NEAR patched call/jmp!?", patchedAddr);
                exit(255);
            }

            // FAR !
            uint64_t targetAddr = 0;
            bool fixedTarget = false;

            // If a BRANCH, treat this like a RET, this is the end unless we have a JMP to a point after this
            //uint64_t addr = x86_get_address(target);
            log("trap: 0x%llx: %s: FAR: op=%p, type=%d", patchedAddr, insntype, target, target->type);

            switch (target->type)
            {
                case op_register:
                    log("trap: 0x%llx: %s: register: %d", patchedAddr, insntype, target->data.reg.id);
                    targetAddr = getRegister(target->data.reg, ucontext);
                    log("trap: 0x%llx: %s: register: targetAddr=0x%llx", patchedAddr, insntype, targetAddr);
                    break;
                case op_relative_far:
                    targetAddr = patch->insn.addr + target->data.relative_far + patch->insn.size;
                    fixedTarget = true;
                    log("trap: 0x%llx: %s: Relative FAR: 0x%llx", patchedAddr, insntype, targetAddr);
                    break;
                case op_expression:
                    log("trap: 0x%llx: %s: scale=%d, index=%s (%d), base=%s, disp=%d",
                        patchedAddr,
                        insntype,
                        target->data.expression.scale,
                        target->data.expression.index.name,
                        target->data.expression.index.type,
                        target->data.expression.base.name,
                        target->data.expression.disp);
                    if (target->data.expression.scale == 0 &&
                        target->data.expression.index.type == 0 &&
                        target->data.expression.base.type == reg_pc &&
                        target->data.expression.disp != 0)
                    {
                        uint64_t* ea = (uint64_t*)(patch->insn.addr + patch->insn.size + target->data.expression.disp);

                        log("trap: 0x%llx: %s: Relative to IP, ea: %p", patchedAddr, insntype, ea);
                        targetAddr = *ea;
                        log("trap: 0x%llx: %s: Relative to IP, value: 0x%llx", patchedAddr, insntype, targetAddr);
                        fixedTarget = true;
                    }
                    else
                    {
                        int64_t index = getRegister(target->data.expression.index, ucontext);
                        int64_t base = getRegister(target->data.expression.base, ucontext);

                        log("trap: 0x%llx: %s: index=0x%llx, base=0x%llx", patchedAddr, insntype, index, base);
                        uint64_t* ea = (uint64_t*)(targetAddr = base + (index * target->data.expression.scale) + target->data.expression.disp);
                        log("trap: 0x%llx: %s: ea=0x%llx", patchedAddr, insntype, ea);
                        targetAddr = *ea;
                        log("trap: 0x%llx: %s: targetAddr=0x%llx", patchedAddr, insntype, targetAddr);
//exit(255);
                    }
                    break;

                default:
                    log("trap: 0x%llx: %s: Unhandled type: %d", patchedAddr, insntype, target->type);
                    exit(255);
            }

            if (targetAddr < 1024)
            {
                log("trap: 0x%llx: %s: targetAddr is in zero page!", patchedAddr, insntype);
                exit(255);
            }

            bool isPatched = m_patcher.isPatched(targetAddr);
            log("trap: PATCH_CALL: targetAddr=0x%llx, isPatched=%d", targetAddr, isPatched);
            if (!isPatched)
            {
                m_patcher.patch(targetAddr);
            }

            if (fixedTarget)
            {
                *((uint8_t*)patchedAddr) = patch->patchedByte;
                ucontext->uc_mcontext->__ss.__rip--;
            }
            else
            {
                ucontext->uc_mcontext->__ss.__rip = targetAddr;
                if (patch->insn.type == insn_jmp)
                {
                }
                else if (patch->insn.type == insn_jcc)
                {
                    log("trap: PATCH_CALL: A BRANCHCC without a fixed target!?");

                    exit(255);
                }
                else
                {
                    // Push the return address on to the stack
                    ucontext->uc_mcontext->__ss.__rsp -= 8;

                    uint64_t* stack = (uint64_t*)ucontext->uc_mcontext->__ss.__rsp;
                    uint64_t returnAddr = patch->insn.addr + patch->insn.size;
                    *stack = returnAddr;
                    log("trap: PATCH_CALL: Calling a non fixed address 0x%llx: returnAddr=%p", targetAddr, returnAddr);
                }
            }
        } break;

        case PATCH_SYSCALL:
        {
            int syscall = ucontext->uc_mcontext->__ss.__rax;
#ifdef DEBUG
            log("trap: PATCH_SYSCALL: Syscall: %lld",  syscall);
#endif
            m_kernel.syscall(syscall, ucontext);

            // Skip it!
            ucontext->uc_mcontext->__ss.__rip++;
        } break;

        case PATCH_FS:
        {
#ifdef DEBUG
            log("trap: PATCH_FS");
#endif
            execFSInstruction((uint8_t*)(patchedAddr + 1), patch->patchedByte, ucontext);
        } break;

        default:
            log("trap: Unhandled patch type: type=%d", patch->type);
            exit(255);
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
        log("setSingleStep: Failed to get thread state: res=%d, err=%d", res, err);
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
        log("setSingleStep: Failed to set thread state: res=%d, err=%d", res, err);
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
        log("checkSingleStep: Failed to get thread state: res=%d, err=%d", res, err);
        exit(1);
    }
    log("checkSingleStep: rflags=0x%llx, T=%d", gp_regs.uts.ts64.__rflags, !!(gp_regs.uts.ts64.__rflags & X86_EFLAGS_T));
}

bool LineProcess::request(ProcessRequest* request)
{
#ifdef DEBUG
    log("request: Adding request...");
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

LineProcess* LineProcess::getProcess()
{
    return g_process;
}

