
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include "line.h"

#define X86_EFLAGS_T 0x100UL

static Line* g_line = NULL;
static ElfProcess* g_elfProcess = NULL;

Line::Line()
{
    g_line = this;
}

Line::~Line()
{
}

bool Line::open(const char* elfpath)
{
    m_elfBinary.load(elfpath);
    return true;
}

bool Line::execute()
{
    m_elfBinary.map();

    pid_t pid = fork();
    if (pid == 0)
    {
        g_elfProcess = new ElfProcess(this);
        g_elfProcess->start();

        // Should never get here!
        exit(0);
    }

    m_elfPid = pid;

    //signal(SIGTRAP, sigtrap_handler);
    //signal(SIGCHLD, sigchld_handler);
    printf("line: Parent! child=%d\n", pid);

    task_t  port;
    int res;
    res = task_for_pid(mach_task_self(), pid, &port);
    printf("line: Parent: res=%d, port=%u\n", res, port);

    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    task_threads(port, &thread_list, &thread_count);
    printf("line: Parent: Thread count: %d\n", thread_count);

    // Set the Trace flag on the child
    x86_thread_state_t gp_regs;
    unsigned int gp_count = x86_THREAD_STATE_COUNT;
    res = thread_get_state(thread_list[0], x86_THREAD_STATE, (thread_state_t) & gp_regs, &gp_count);
    if (res != 0)
    {
        int err = errno;
        printf("line: Parent: Failed to get thread state: res=%d, err=%d\n", res, err);
        exit(1);
    }

    printf("line: Parent: state res=%d, gp_count=%u\n", res, gp_count);
    printf("line: Parent: EIP=0x%llx\n", gp_regs.uts.ts64.__rip);

    gp_regs.uts.ts64.__rflags = (gp_regs.uts.ts64.__rflags & ~X86_EFLAGS_T) | X86_EFLAGS_T;
    //gp_regs.uts.ts64.__rip = (uint64_t)test;
    res = thread_set_state (thread_list[0], x86_THREAD_STATE,
                             (thread_state_t) &gp_regs, gp_count);

    printf("line: parent: resuming...\n");
    res = task_resume(port);
    printf("line: parent: res=%d\n", res);

    wait(0);
    printf("line: parent: Child has finished\n");

    return true;
}

ElfProcess::ElfProcess(Line* line)
{
    m_line = line;
}

bool ElfProcess::start()
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
    environ[1] = NULL;

    Elf64_auxv_t auxv[2];
    environ[1] = (char*)auxv;

    char randbytes[16];
    int i;
    for (i = 0; i < 16; i++)
    {
        randbytes[i] = i;
    }
    auxv[0].a_type = AT_RANDOM;
    auxv[0].a_un.a_val = (uint64_t)randbytes;

    auxv[1].a_type = AT_NULL;

    printf("line: child: environ=%p\n", environ);
    printf("line: child: auxv=%p\n", auxv);
    printf("line: child: randbytes=%p\n", randbytes);

    // Set up brk pointer
    uint64_t end = m_line->getElfBinary()->findSymbol("_end")->st_value;
    printf("line: child: sys_brk: end=0x%llx\n", end);
    m_brk = ALIGN(end, 4096);

    // Set up args
    // 0 "hello"
    // 1 environment
    char** elfArgv = new char*[1];
    elfArgv[0] = (char*)"hello";
    //elfArgv[1] = (char*)environ;

    // Wait for our parent to enable single step tracing etc
    task_suspend(mach_task_self());

    // Execute the ELF (Note, no Elves were harmed...)
    m_line->getElfBinary()->entry(1, elfArgv, environ);

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

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004


#define LINUX_MAP_SHARED      0x01            /* Share changes */
#define LINUX_MAP_PRIVATE     0x02            /* Changes are private */
#define LINUX_MAP_TYPE        0x0f            /* Mask for type of mapping */
#define LINUX_MAP_FIXED       0x10            /* Interpret addr exactly */
#define LINUX_MAP_ANONYMOUS   0x20            /* don't use a file */

struct linux_iovec
  {
    void *iov_base;     /* Pointer to data.  */
    size_t iov_len;     /* Length of data.  */
  };

#define LINUX_OLD_UTSNAME_LENGTH 65
struct  linux_oldutsname {
        char    sysname[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Name of OS */
        char    nodename[LINUX_OLD_UTSNAME_LENGTH]; /* [XSI] Name of this network node */
        char    release[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Release level */
        char    version[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Version level */
        char    machine[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Hardware type */
};

void printregs(ucontext_t* ucontext)
{
    printf("rax=0x%llx, rbx=0x%llx, rcx=0x%llx, rdx=0x%llx\n",
        ucontext->uc_mcontext->__ss.__rax,
        ucontext->uc_mcontext->__ss.__rbx,
        ucontext->uc_mcontext->__ss.__rcx,
        ucontext->uc_mcontext->__ss.__rdx);
    printf("rdi=0x%llx, rsi=0x%llx, rbp=0x%llx, rsp=0x%llx\n",
        ucontext->uc_mcontext->__ss.__rdi,
        ucontext->uc_mcontext->__ss.__rsi,
        ucontext->uc_mcontext->__ss.__rbp,
        ucontext->uc_mcontext->__ss.__rsp);
    printf("r8=0x%llx, r9=0x%llx, r10=0x%llx, r11=0x%llx\n",
        ucontext->uc_mcontext->__ss.__r8,
        ucontext->uc_mcontext->__ss.__r9,
        ucontext->uc_mcontext->__ss.__r10,
        ucontext->uc_mcontext->__ss.__r11);
    printf("r12=0x%llx, r13=0x%llx, r14=0x%llx, r15=0x%llx\n",
        ucontext->uc_mcontext->__ss.__r12,
        ucontext->uc_mcontext->__ss.__r13,
        ucontext->uc_mcontext->__ss.__r14,
        ucontext->uc_mcontext->__ss.__r15);
    printf("rip=0x%llx, rflags=0x%llx\n",
        ucontext->uc_mcontext->__ss.__rip,
        ucontext->uc_mcontext->__ss.__rflags);
    printf("cs=0x%llx, fs=0x%llx, gs=0x%llx\n",
        ucontext->uc_mcontext->__ss.__cs,
        //ucontext->uc_mcontext->__ss.__ds,
        //ucontext->uc_mcontext->__ss.__es,
        ucontext->uc_mcontext->__ss.__fs,
        ucontext->uc_mcontext->__ss.__gs);
}

void ElfProcess::error(int sig, siginfo_t* info, ucontext_t* ucontext)
{
    printf(
        "ElfProcess::error: sig=%d, errno=%d, address=%p\n",
        sig,
        info->si_errno,
        info->si_addr);
    printregs(ucontext);

    exit(1);
}

void ElfProcess::trap(siginfo_t* info, ucontext_t* ucontext)
{
    //x86_thread_state64_t*
    if ((uint64_t)info->si_addr < 0x7fff90000000ull)
    {
        //printf("child_signal_handler: sig=%d, errno=%d, address=%p\n", sig, info->si_errno, info->si_addr);
        //printf("child_signal_handler:  -> RAX=0x%llx\n", ucontext->uc_mcontext->__ss.__rax);
    }

    if ((uint64_t)info->si_addr == 0x400fb0)
    {
printregs(ucontext);
    }

    uint8_t* addr = (uint8_t*)info->si_addr;
    if (*addr == 0x0f && *(addr + 1) == 0x05)
    {
        printf("trap: errno=%d, address=%p: SYSCALL\n", info->si_errno, info->si_addr);
        //printf("child_signal_handler:  -> SYSCALL: RAX=%p\n", ucontext->uc_mcontext->__ss.__rax);
        int syscall = ucontext->uc_mcontext->__ss.__rax;
        switch (syscall)
        {
            case 0x2: // open
            {
                const char* filename = (const char*)(ucontext->uc_mcontext->__ss.__rdi);
                int flags = ucontext->uc_mcontext->__ss.__rsi;
                int mode = ucontext->uc_mcontext->__ss.__rdx;
                printf("child_signal_handler:  -> sys_open: filename=%s, flags=0x%x, mode=0x%x\n", filename, flags, mode);

                int fd = open(filename, flags, mode);
                printf("child_signal_handler:  -> sys_open: fd=%d\n", fd);

                ucontext->uc_mcontext->__ss.__rax = fd;
            } break;

            case 0x9: // sys_mmap
            {
                uint64_t addr = ucontext->uc_mcontext->__ss.__rdi;
                uint64_t len = ucontext->uc_mcontext->__ss.__rsi;
                uint64_t prot = ucontext->uc_mcontext->__ss.__rdx;
                uint64_t flags = ucontext->uc_mcontext->__ss.__r10;
                uint64_t fd = ucontext->uc_mcontext->__ss.__r8;
                uint64_t off = ucontext->uc_mcontext->__ss.__r9;

                int darwinFlags = 0;

                if (flags & LINUX_MAP_SHARED)
                {
                    darwinFlags |= MAP_SHARED;
                }
                if (flags & LINUX_MAP_PRIVATE)
                {
                    darwinFlags |= MAP_PRIVATE;
                }
                if (flags & LINUX_MAP_FIXED)
                {
                    darwinFlags |= MAP_FIXED;
                }
                if (flags & LINUX_MAP_ANONYMOUS)
                {
                    darwinFlags |= MAP_ANON;
                    fd = 0;
                }
                prot &= 0x7;
                printf("child_signal_handler: sys_mmap: addr=0x%llx, len=%llu, prot=0x%llx, flags=0x%llx->%x, fd=%lld, off=%lld\n",
                    addr, len, prot, flags, darwinFlags, fd, off);
                void* result = mmap((void*)addr, len, prot, darwinFlags, fd, off);
                int err = errno;
                printf("child_signal_handler: sys_mmap: -> result=%p, errno=%d\n", result, err);

                ucontext->uc_mcontext->__ss.__rax = (uint64_t)result;
        } break;

            case 0xc: // sys_brk
            {
                uint64_t brkarg = ucontext->uc_mcontext->__ss.__rdi;
                printf("child_signal_handler: sys_brk: brkarg=0x%llx\n", brkarg);

                if (brkarg == 0)
                {
                    ucontext->uc_mcontext->__ss.__rax = (uint64_t)m_brk;
                }
                else
                {
                    uint64_t newbrk = ALIGN(brkarg, 4096);
                    uint64_t len = newbrk - m_brk;
                    printf("child_signal_handler: sys_brk: newbrk=0x%llx, len=%llx\n", newbrk, len);
                    void* maddr = mmap((void*)m_brk, len,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_FIXED | MAP_ANON | MAP_PRIVATE,
                        -1,
                        0);
                    printf("child_signal_handler: sys_brk:  -> maddr=%p\n", maddr);
                    //void* brkres = brk((const void*)brkarg);

                    ucontext->uc_mcontext->__ss.__rax = (uint64_t)newbrk;
                }
                printf("child_signal_handler: sys_brk: returning: 0x%llx\n", ucontext->uc_mcontext->__ss.__rax);

            } break;

            case 0x14: // sys_writev
            {
                int fd = ucontext->uc_mcontext->__ss.__rdi;
                iovec* vec = (iovec*)(ucontext->uc_mcontext->__ss.__rsi);
                unsigned long vlen = ucontext->uc_mcontext->__ss.__rdx;
                printf("child_signal_handler:  -> sys_writev: fd=%d, vec=%p (%p, %lu), vlen=%lu\n", fd, vec, vec->iov_base, vec->iov_len, vlen);

                ssize_t res = writev(fd, vec, vlen);
                printf("child_signal_handler:  -> sys_writev: res=%lu\n", res);
ucontext->uc_mcontext->__ss.__rax = res;
            } break;

            case 0x3f: // old uname
            {
                linux_oldutsname* utsname = (linux_oldutsname*)ucontext->uc_mcontext->__ss.__rdi;
                printf("child_signal_handler: sys_utsname: utsname=%p\n", utsname);
                strcpy(utsname->sysname, "Linux");
                strcpy(utsname->nodename, "LinuxOnMac");
                strcpy(utsname->release, "4.4.24");
                strcpy(utsname->version, "4.4.24"); // The version I've been using as a reference
                strcpy(utsname->machine, "x86_64");
                ucontext->uc_mcontext->__ss.__rax = 0;
            } break;

            case 158: // sys_arch_prctl
            {
                int option = ucontext->uc_mcontext->__ss.__rdi;
                uint64_t addr = (uint64_t)ucontext->uc_mcontext->__ss.__rsi;

                printf("child_signal_handler: sys_arch_prctl: option=0x%x, addr=%llx\n", option, addr);
                printf("child_signal_handler: sys_arch_prctl: Current: fs=0x%llx, gs=0x%llx\n", ucontext->uc_mcontext->__ss.__fs, ucontext->uc_mcontext->__ss.__gs);

                switch (option)
                {
                    case ARCH_SET_GS:
                        ucontext->uc_mcontext->__ss.__gs = (uint64_t)addr;
                        ucontext->uc_mcontext->__ss.__rax = 0;
                        break;

                    case ARCH_SET_FS:
                    {
                        m_fs = (uint64_t)addr;
                        ucontext->uc_mcontext->__ss.__rax = 0;

                    } break;

                    case ARCH_GET_FS:
                        ucontext->uc_mcontext->__ss.__rax = m_fs;
                        break;

                    case ARCH_GET_GS:
                        ucontext->uc_mcontext->__ss.__rax = ucontext->uc_mcontext->__ss.__gs;
                        break;
                }
            } break;

            default:
                printf("child_signal_handler: ERROR: Unhandled syscall: %d (0x%x)\n", syscall, syscall);
                exit(1);
                break;
        }

        // Skip it!
        // This has the side effect of not stepping through the next instruction
        // Hopefully we won't have two syscalls in a row!
        ucontext->uc_mcontext->__ss.__rip += 2;
    }

}

void proc__task__vmmap();
int main(int argc, char** argv)
{
    Line line;
    line.open("hello");
    line.execute();
    return 0;
}

