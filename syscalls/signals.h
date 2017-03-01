#ifndef __LINE_SYSCALLS_SIGNALS_H_
#define __LINE_SYSCALLS_SIGNALS_H_

#define LINUX_WNOHANG         0x00000001
#define LINUX_WUNTRACED       0x00000002
#define LINUX_WSTOPPED        LINUX_WUNTRACED
#define LINUX_WEXITED         0x00000004
#define LINUX_WCONTINUED      0x00000008
#define LINUX_WNOWAIT         0x01000000      /* Don't reap, just poll status.  */

#define LINUX_SS_ONSTACK      1
#define LINUX_SS_DISABLE      2

typedef struct sigaltstack
{
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} linux_stack_t;

#endif
