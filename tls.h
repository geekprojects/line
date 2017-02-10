#ifndef __LINE_TLS_H_
#define __LINE_TLS_H_

typedef struct list_head
{
    struct list_head *next;
    struct list_head *prev;
} list_t;

typedef struct
{
    int i[4];
} __128bits;

typedef union dtv
{
    size_t counter;
    struct
    {
        void *val;
        bool is_static;
    } pointer;
} dtv_t;

typedef struct
{
    void *tcb;            /* Pointer to the TCB.  Not necessarily the
                           thread descriptor used by libpthread.  */
    dtv_t *dtv;
    void *self;           /* Pointer to the thread descriptor.  */
    int multiple_threads;
    int gscope_flag;
    uintptr_t sysinfo;
    uintptr_t stack_guard;
    uintptr_t pointer_guard;
    unsigned long int vgetcpu_cache[2];
# ifndef __ASSUME_PRIVATE_FUTEX
    int private_futex;
# else
    int __glibc_reserved1;
# endif
    int rtld_must_xmm_save;
    /* Reservation of some values for the TM ABI.  */
    void *__private_tm[4];
    /* GCC split stack support.  */
    void *__private_ss;
    long int __glibc_reserved2;
    /* Have space for the post-AVX register size.  */
    __128bits rtld_savespace_sse[8][4] __attribute__ ((aligned (32)));

    void *__padding[8];
} tcbhead_t;

struct pthread
{
    union
    {
        /* This overlaps the TCB as used for TLS without threads (see tls.h).  */
        tcbhead_t header;
    } header;

    /* This descriptor's link on the `stack_used' or `__stack_user' list.  */
    list_t list;

    /* Thread ID - which is also a 'is this thread descriptor (and
       therefore stack) used' flag.  */
    pid_t tid;

    /* Process ID - thread group ID in kernel speak.  */
    pid_t pid;
};

#endif
