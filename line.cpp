
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
/*
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
*/

#include "line.h"
#include "elfprocess.h"

#define X86_EFLAGS_T 0x100UL

static Line* g_line = NULL;

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

    pid_t pid = fork();
    if (pid == 0)
    {
        m_elfBinary.map();

        ElfProcess* elfProcess = new ElfProcess(this);
        elfProcess->start();

        // Should never get here!
        wait(0);
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

//while (true)
//{
int s;
    wait(&s);
    printf("line: parent: Wait returned!\n");
    printf("line: parent: WIFEXITSED=%d\n", WIFEXITED(s));
    printf("line: parent: WIFSIGNALED=%d\n", WIFSIGNALED(s));
    printf("line: parent: WIFSTOPPED=%d\n", WIFSTOPPED(s));
    printf("line: parent: WEXITSTATUS=%d\n", WEXITSTATUS(s));
    printf("line: parent: WTERMSIG=%d\n", WTERMSIG(s));
    printf("line: parent: WCOREDUMP=%d\n", WCOREDUMP(s));
    printf("line: parent: WSTOPSIG=%d\n", WSTOPSIG(s));
//if (WIFEXITED(s))
//{
//break;
//}
//}
fflush(stdout);
//sleep(1);

    return true;
}

