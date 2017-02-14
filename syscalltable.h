    &LinuxKernel::sys_read,	// 0: sys_read unsigned int fd,char *buf,size_t count
    &LinuxKernel::sys_write,	// 1: sys_write unsigned int fd,const char *buf,size_t count
    &LinuxKernel::sys_open,	// 2: sys_open const char *filename,int flags,int mode
    &LinuxKernel::sys_close,	// 3: sys_close unsigned int fd
    &LinuxKernel::sys_stat,	// 4: sys_stat const char *filename,struct stat *statbuf
    &LinuxKernel::sys_fstat,	// 5: sys_fstat unsigned int fd,struct stat *statbuf
    &LinuxKernel::sys_lstat,	// 6: sys_lstat fconst char *filename,struct stat *statbuf
    &LinuxKernel::sys_notimplemented,	// 7: sys_poll struct poll_fd *ufds,unsigned int nfds,long timeout_msecs
    &LinuxKernel::sys_lseek,	// 8: sys_lseek unsigned int fd,off_t offset,unsigned int origin
    &LinuxKernel::sys_mmap,	// 9: sys_mmap unsigned long addr,unsigned long len,unsigned long prot,unsigned long flags,unsigned long fd,unsigned long off
    &LinuxKernel::sys_mprotect,	// 10: sys_mprotect unsigned long start,size_t len,unsigned long prot
    &LinuxKernel::sys_munmap,	// 11: sys_munmap unsigned long addr,size_t len
    &LinuxKernel::sys_brk,	// 12: sys_brk unsigned long brk
    &LinuxKernel::sys_rt_sigaction,	// 13: sys_rt_sigaction int sig,const struct sigaction *act,struct sigaction *oact,size_t sigsetsize
    &LinuxKernel::sys_rt_sigprocmask,	// 14: sys_rt_sigprocmask int how,sigset_t *nset,sigset_t *oset,size_t sigsetsize
    &LinuxKernel::sys_notimplemented,	// 15: sys_rt_sigreturn unsigned long __unused
    &LinuxKernel::sys_ioctl,	// 16: sys_ioctl unsigned int fd,unsigned int cmd,unsigned long arg
    &LinuxKernel::sys_notimplemented,	// 17: sys_pread64 unsigned long fd,char *buf,size_t count,loff_t pos
    &LinuxKernel::sys_notimplemented,	// 18: sys_pwrite64 unsigned int fd,const char *buf,size_t count,loff_t pos
    &LinuxKernel::sys_notimplemented,	// 19: sys_readv unsigned long fd,const struct iovec *vec,unsigned long vlen
    &LinuxKernel::sys_writev,	// 20: sys_writev unsigned long fd,const struct iovec *vec,unsigned long vlen
    &LinuxKernel::sys_access,	// 21: sys_access const char *filename,int mode
    &LinuxKernel::sys_pipe,	// 22: sys_pipe int *filedes
    &LinuxKernel::sys_select,	// 23: sys_select int n,fd_set *inp,fd_set *outp,fd_set*exp,struct timeval *tvp
    &LinuxKernel::sys_notimplemented,	// 24: sys_sched_yield 
    &LinuxKernel::sys_notimplemented,	// 25: sys_mremap unsigned long addr,unsigned long old_len,unsigned long new_len,unsigned long flags,unsigned long new_addr
    &LinuxKernel::sys_msync,	// 26: sys_msync unsigned long start,size_t len,int flags
    &LinuxKernel::sys_mincore,	// 27: sys_mincore unsigned long start,size_t len,unsigned char *vec
    &LinuxKernel::sys_notimplemented,	// 28: sys_madvise unsigned long start,size_t len_in,int behavior
    &LinuxKernel::sys_notimplemented,	// 29: sys_shmget key_t key,size_t size,int shmflg
    &LinuxKernel::sys_notimplemented,	// 30: sys_shmat int shmid,char *shmaddr,int shmflg
    &LinuxKernel::sys_notimplemented,	// 31: sys_shmctl int shmid,int cmd,struct shmid_ds *buf
    &LinuxKernel::sys_dup,	// 32: sys_dup unsigned int fildes
    &LinuxKernel::sys_dup2,	// 33: sys_dup2 unsigned int oldfd,unsigned int newfd
    &LinuxKernel::sys_notimplemented,	// 34: sys_pause 
    &LinuxKernel::sys_nanosleep,	// 35: sys_nanosleep struct timespec *rqtp,struct timespec *rmtp
    &LinuxKernel::sys_notimplemented,	// 36: sys_getitimer int which,struct itimerval *value
    &LinuxKernel::sys_notimplemented,	// 37: sys_alarm unsigned int seconds
    &LinuxKernel::sys_notimplemented,	// 38: sys_setitimer int which,struct itimerval *value,struct itimerval *ovalue
    &LinuxKernel::sys_getpid,	// 39: sys_getpid 
    &LinuxKernel::sys_notimplemented,	// 40: sys_sendfile int out_fd,int in_fd,off_t *offset,size_t count
    &LinuxKernel::sys_socket,	// 41: sys_socket int family,int type,int protocol
    &LinuxKernel::sys_connect,	// 42: sys_connect int fd,struct sockaddr *uservaddr,int addrlen
    &LinuxKernel::sys_notimplemented,	// 43: sys_accept int fd,struct sockaddr *upeer_sockaddr,int *upeer_addrlen
    &LinuxKernel::sys_notimplemented,	// 44: sys_sendto int fd,void *buff,size_t len,unsigned flags,struct sockaddr *addr,int addr_len
    &LinuxKernel::sys_notimplemented,	// 45: sys_recvfrom int fd,void *ubuf,size_t size,unsigned flags,struct sockaddr *addr,int *addr_len
    &LinuxKernel::sys_notimplemented,	// 46: sys_sendmsg int fd,struct msghdr *msg,unsigned flags
    &LinuxKernel::sys_notimplemented,	// 47: sys_recvmsg int fd,struct msghdr *msg,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 48: sys_shutdown int fd,int how
    &LinuxKernel::sys_notimplemented,	// 49: sys_bind int fd,struct sokaddr *umyaddr,int addrlen
    &LinuxKernel::sys_notimplemented,	// 50: sys_listen int fd,int backlog
    &LinuxKernel::sys_notimplemented,	// 51: sys_getsockname int fd,struct sockaddr *usockaddr,int *usockaddr_len
    &LinuxKernel::sys_notimplemented,	// 52: sys_getpeername int fd,struct sockaddr *usockaddr,int *usockaddr_len
    &LinuxKernel::sys_notimplemented,	// 53: sys_socketpair int family,int type,int protocol,int *usockvec
    &LinuxKernel::sys_notimplemented,	// 54: sys_setsockopt int fd,int level,int optname,char *optval,int optlen
    &LinuxKernel::sys_notimplemented,	// 55: sys_getsockopt int fd,int level,int optname,char *optval,int *optlen
    &LinuxKernel::sys_clone,	// 56: sys_clone unsigned long clone_flags,unsigned long newsp,void *parent_tid,void *child_tid
    &LinuxKernel::sys_notimplemented,	// 57: sys_fork 
    &LinuxKernel::sys_notimplemented,	// 58: sys_vfork 
    &LinuxKernel::sys_execve,	// 59: sys_execve const char *filename,const char *const argv[],const char *const envp[]
    &LinuxKernel::sys_notimplemented,	// 60: sys_exit int error_code
    &LinuxKernel::sys_wait4,	// 61: sys_wait4 pid_t upid,int *stat_addr,int options,struct rusage *ru
    &LinuxKernel::sys_notimplemented,	// 62: sys_kill pid_t pid,int sig
    &LinuxKernel::sys_uname,	// 63: sys_uname struct old_utsname *name
    &LinuxKernel::sys_notimplemented,	// 64: sys_semget key_t key,int nsems,int semflg
    &LinuxKernel::sys_notimplemented,	// 65: sys_semop int semid,struct sembuf *tsops,unsigned nsops
    &LinuxKernel::sys_notimplemented,	// 66: sys_semctl int semid,int semnum,int cmd,union semun arg
    &LinuxKernel::sys_notimplemented,	// 67: sys_shmdt char *shmaddr
    &LinuxKernel::sys_notimplemented,	// 68: sys_msgget key_t key,int msgflg
    &LinuxKernel::sys_notimplemented,	// 69: sys_msgsnd int msqid,struct msgbuf *msgp,size_t msgsz,int msgflg
    &LinuxKernel::sys_notimplemented,	// 70: sys_msgrcv int msqid,struct msgbuf *msgp,size_t msgsz,long msgtyp,int msgflg
    &LinuxKernel::sys_notimplemented,	// 71: sys_msgctl int msqid,int cmd,struct msqid_ds *buf
    &LinuxKernel::sys_fcntl,	// 72: sys_fcntl unsigned int fd,unsigned int cmd,unsigned long arg
    &LinuxKernel::sys_notimplemented,	// 73: sys_flock unsigned int fd,unsigned int cmd
    &LinuxKernel::sys_fsync,	// 74: sys_fsync unsigned int fd
    &LinuxKernel::sys_notimplemented,	// 75: sys_fdatasync unsigned int fd
    &LinuxKernel::sys_notimplemented,	// 76: sys_truncate const char *path,long length
    &LinuxKernel::sys_ftruncate,	// 77: sys_ftruncate unsigned int fd,unsigned long length
    &LinuxKernel::sys_getdents,	// 78: sys_getdents unsigned int fd,struct linux_dirent *dirent,unsigned int count
    &LinuxKernel::sys_getcwd,	// 79: sys_getcwd char *buf,unsigned long size
    &LinuxKernel::sys_chdir,	// 80: sys_chdir const char *filename
    &LinuxKernel::sys_fchdir,	// 81: sys_fchdir unsigned int fd
    &LinuxKernel::sys_rename,	// 82: sys_rename const char *oldname,const char *newname
    &LinuxKernel::sys_mkdir,	// 83: sys_mkdir const char *pathname,int mode
    &LinuxKernel::sys_notimplemented,	// 84: sys_rmdir const char *pathname
    &LinuxKernel::sys_creat,	// 85: sys_creat const char *pathname,int mode
    &LinuxKernel::sys_notimplemented,	// 86: sys_link const char *oldname,const char *newname
    &LinuxKernel::sys_unlink,	// 87: sys_unlink const char *pathname
    &LinuxKernel::sys_notimplemented,	// 88: sys_symlink const char *oldname,const char *newname
    &LinuxKernel::sys_readlink,	// 89: sys_readlink const char *path,char *buf,int bufsiz
    &LinuxKernel::sys_notimplemented,	// 90: sys_chmod const char *filename,mode_t mode
    &LinuxKernel::sys_fchmod,	// 91: sys_fchmod unsigned int fd,mode_t mode
    &LinuxKernel::sys_notimplemented,	// 92: sys_chown const char *filename,uid_t user,gid_t group
    &LinuxKernel::sys_notimplemented,	// 93: sys_fchown unsigned int fd,uid_t user,gid_t group
    &LinuxKernel::sys_notimplemented,	// 94: sys_lchown const char *filename,uid_t user,gid_t group
    &LinuxKernel::sys_umask,	// 95: sys_umask int mask
    &LinuxKernel::sys_notimplemented,	// 96: sys_gettimeofday struct timeval *tv,struct timezone *tz
    &LinuxKernel::sys_getrlimit,	// 97: sys_getrlimit unsigned int resource,struct rlimit *rlim
    &LinuxKernel::sys_notimplemented,	// 98: sys_getrusage int who,struct rusage *ru
    &LinuxKernel::sys_notimplemented,	// 99: sys_sysinfo struct sysinfo *info
    &LinuxKernel::sys_notimplemented,	// 100: sys_times struct sysinfo *info
    &LinuxKernel::sys_notimplemented,	// 101: sys_ptrace long request,long pid,unsigned long addr,unsigned long data
    &LinuxKernel::sys_getuid,	// 102: sys_getuid 
    &LinuxKernel::sys_notimplemented,	// 103: sys_syslog int type,char *buf,int len
    &LinuxKernel::sys_getgid,	// 104: sys_getgid 
    &LinuxKernel::sys_notimplemented,	// 105: sys_setuid uid_t uid
    &LinuxKernel::sys_notimplemented,	// 106: sys_setgid gid_t gid
    &LinuxKernel::sys_geteuid,	// 107: sys_geteuid 
    &LinuxKernel::sys_getegid,	// 108: sys_getegid 
    &LinuxKernel::sys_setpgid,	// 109: sys_setpgid pid_t pid,pid_t pgid
    &LinuxKernel::sys_getppid,	// 110: sys_getppid 
    &LinuxKernel::sys_getpgrp,	// 111: sys_getpgrp 
    &LinuxKernel::sys_notimplemented,	// 112: sys_setsid 
    &LinuxKernel::sys_notimplemented,	// 113: sys_setreuid uid_t ruid,uid_t euid
    &LinuxKernel::sys_notimplemented,	// 114: sys_setregid gid_t rgid,gid_t egid
    &LinuxKernel::sys_getgroups,	// 115: sys_getgroups int gidsetsize,gid_t *grouplist
    &LinuxKernel::sys_notimplemented,	// 116: sys_setgroups int gidsetsize,gid_t *grouplist
    &LinuxKernel::sys_notimplemented,	// 117: sys_setresuid uid_t *ruid,uid_t *euid,uid_t *suid
    &LinuxKernel::sys_notimplemented,	// 118: sys_getresuid uid_t *ruid,uid_t *euid,uid_t *suid
    &LinuxKernel::sys_notimplemented,	// 119: sys_setresgid gid_t rgid,gid_t egid,gid_t sgid
    &LinuxKernel::sys_notimplemented,	// 120: sys_getresgid gid_t *rgid,gid_t *egid,gid_t *sgid
    &LinuxKernel::sys_notimplemented,	// 121: sys_getpgid pid_t pid
    &LinuxKernel::sys_notimplemented,	// 122: sys_setfsuid uid_t uid
    &LinuxKernel::sys_notimplemented,	// 123: sys_setfsgid gid_t gid
    &LinuxKernel::sys_notimplemented,	// 124: sys_getsid pid_t pid
    &LinuxKernel::sys_notimplemented,	// 125: sys_capget cap_user_header_t header,cap_user_data_t dataptr
    &LinuxKernel::sys_notimplemented,	// 126: sys_capset cap_user_header_t header,const cap_user_data_t data
    &LinuxKernel::sys_notimplemented,	// 127: sys_rt_sigpending sigset_t *set,size_t sigsetsize
    &LinuxKernel::sys_notimplemented,	// 128: sys_rt_sigtimedwait const sigset_t *uthese,siginfo_t *uinfo,const struct timespec *uts,size_t sigsetsize
    &LinuxKernel::sys_notimplemented,	// 129: sys_rt_sigqueueinfo pid_t pid,int sig,siginfo_t *uinfo
    &LinuxKernel::sys_rt_sigsuspend,	// 130: sys_rt_sigsuspend sigset_t *unewset,size_t sigsetsize
    &LinuxKernel::sys_notimplemented,	// 131: sys_sigaltstack const stack_t *uss,stack_t *uoss
    &LinuxKernel::sys_notimplemented,	// 132: sys_utime char *filename,struct utimbuf *times
    &LinuxKernel::sys_notimplemented,	// 133: sys_mknod const char *filename,umode_t mode,unsigned dev
    &LinuxKernel::sys_notimplemented,	// 134: sys_uselib NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 135: sys_personality unsigned int personality
    &LinuxKernel::sys_notimplemented,	// 136: sys_ustat unsigned dev,struct ustat *ubuf
    &LinuxKernel::sys_notimplemented,	// 137: sys_statfs const char *pathname,struct statfs *buf
    &LinuxKernel::sys_notimplemented,	// 138: sys_fstatfs unsigned int fd,struct statfs *buf
    &LinuxKernel::sys_notimplemented,	// 139: sys_sysfs int option,unsigned long arg1,unsigned long arg2
    &LinuxKernel::sys_notimplemented,	// 140: sys_getpriority int which,int who
    &LinuxKernel::sys_notimplemented,	// 141: sys_setpriority int which,int who,int niceval
    &LinuxKernel::sys_notimplemented,	// 142: sys_sched_setparam pid_t pid,struct sched_param *param
    &LinuxKernel::sys_notimplemented,	// 143: sys_sched_getparam pid_t pid,struct sched_param *param
    &LinuxKernel::sys_notimplemented,	// 144: sys_sched_setscheduler pid_t pid,int policy,struct sched_param *param
    &LinuxKernel::sys_notimplemented,	// 145: sys_sched_getscheduler pid_t pid
    &LinuxKernel::sys_notimplemented,	// 146: sys_sched_get_priority_max int policy
    &LinuxKernel::sys_notimplemented,	// 147: sys_sched_get_priority_min int policy
    &LinuxKernel::sys_notimplemented,	// 148: sys_sched_rr_get_interval pid_t pid,struct timespec *interval
    &LinuxKernel::sys_mlock,	// 149: sys_mlock unsigned long start,size_t len
    &LinuxKernel::sys_notimplemented,	// 150: sys_munlock unsigned long start,size_t len
    &LinuxKernel::sys_notimplemented,	// 151: sys_mlockall int flags
    &LinuxKernel::sys_notimplemented,	// 152: sys_munlockall 
    &LinuxKernel::sys_notimplemented,	// 153: sys_vhangup 
    &LinuxKernel::sys_notimplemented,	// 154: sys_modify_ldt int func,void *ptr,unsigned long bytecount
    &LinuxKernel::sys_notimplemented,	// 155: sys_pivot_root const char *new_root,const char *put_old
    &LinuxKernel::sys_notimplemented,	// 156: sys__sysctl struct __sysctl_args *args
    &LinuxKernel::sys_notimplemented,	// 157: sys_prctl int option,unsigned long arg2,unsigned long arg3,unsigned long arg4unsigned long arg5
    &LinuxKernel::sys_arch_prctl,	// 158: sys_arch_prctl struct task_struct *task,int code,unsigned long *addr
    &LinuxKernel::sys_notimplemented,	// 159: sys_adjtimex struct timex *txc_p
    &LinuxKernel::sys_setrlimit,	// 160: sys_setrlimit unsigned int resource,struct rlimit *rlim
    &LinuxKernel::sys_notimplemented,	// 161: sys_chroot const char *filename
    &LinuxKernel::sys_notimplemented,	// 162: sys_sync 
    &LinuxKernel::sys_notimplemented,	// 163: sys_acct const char *name
    &LinuxKernel::sys_notimplemented,	// 164: sys_settimeofday struct timeval *tv,struct timezone *tz
    &LinuxKernel::sys_notimplemented,	// 165: sys_mount char *dev_name,char *dir_name,char *type,unsigned long flags,void *data
    &LinuxKernel::sys_notimplemented,	// 166: sys_umount2 const char *target,int flags
    &LinuxKernel::sys_notimplemented,	// 167: sys_swapon const char *specialfile,int swap_flags
    &LinuxKernel::sys_notimplemented,	// 168: sys_swapoff const char *specialfile
    &LinuxKernel::sys_notimplemented,	// 169: sys_reboot int magic1,int magic2,unsigned int cmd,void *arg
    &LinuxKernel::sys_notimplemented,	// 170: sys_sethostname char *name,int len
    &LinuxKernel::sys_notimplemented,	// 171: sys_setdomainname char *name,int len
    &LinuxKernel::sys_notimplemented,	// 172: sys_iopl unsigned int level,struct pt_regs *regs
    &LinuxKernel::sys_notimplemented,	// 173: sys_ioperm unsigned long from,unsigned long num,int turn_on
    &LinuxKernel::sys_notimplemented,	// 174: sys_create_module REMOVED IN Linux 2.6
    &LinuxKernel::sys_notimplemented,	// 175: sys_init_module void *umod,unsigned long len,const char *uargs
    &LinuxKernel::sys_notimplemented,	// 176: sys_delete_module const chat *name_user,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 177: sys_get_kernel_syms REMOVED IN Linux 2.6
    &LinuxKernel::sys_notimplemented,	// 178: sys_query_module REMOVED IN Linux 2.6
    &LinuxKernel::sys_notimplemented,	// 179: sys_quotactl unsigned int cmd,const char *special,qid_t id,void *addr
    &LinuxKernel::sys_notimplemented,	// 180: sys_nfsservctl NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 181: sys_getpmsg NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 182: sys_putpmsg NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 183: sys_afs_syscall NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 184: sys_tuxcall NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 185: sys_security NOT IMPLEMENTED
    &LinuxKernel::sys_gettid,	// 186: sys_gettid 
    &LinuxKernel::sys_notimplemented,	// 187: sys_readahead int fd,loff_t offset,size_t count
    &LinuxKernel::sys_notimplemented,	// 188: sys_setxattr const char *pathname,const char *name,const void *value,size_t size,int flags
    &LinuxKernel::sys_notimplemented,	// 189: sys_lsetxattr const char *pathname,const char *name,const void *value,size_t size,int flags
    &LinuxKernel::sys_notimplemented,	// 190: sys_fsetxattr int fd,const char *name,const void *value,size_t size,int flags
    &LinuxKernel::sys_getxattr,	// 191: sys_getxattr const char *pathname,const char *name,void *value,size_t size
    &LinuxKernel::sys_getxattr,	// 192: sys_lgetxattr const char *pathname,const char *name,void *value,size_t size
    &LinuxKernel::sys_notimplemented,	// 193: sys_fgetxattr int fd,const har *name,void *value,size_t size
    &LinuxKernel::sys_notimplemented,	// 194: sys_listxattr const char *pathname,char *list,size_t size
    &LinuxKernel::sys_notimplemented,	// 195: sys_llistxattr const char *pathname,char *list,size_t size
    &LinuxKernel::sys_notimplemented,	// 196: sys_flistxattr int fd,char *list,size_t size
    &LinuxKernel::sys_notimplemented,	// 197: sys_removexattr const char *pathname,const char *name
    &LinuxKernel::sys_notimplemented,	// 198: sys_lremovexattr const char *pathname,const char *name
    &LinuxKernel::sys_notimplemented,	// 199: sys_fremovexattr int fd,const char *name
    &LinuxKernel::sys_notimplemented,	// 200: sys_tkill pid_t pid,ing sig
    &LinuxKernel::sys_notimplemented,	// 201: sys_time time_t *tloc
    &LinuxKernel::sys_futex,	// 202: sys_futex u32 *uaddr,int op,u32 val,struct timespec *utime,u32 *uaddr2,u32 val3
    &LinuxKernel::sys_notimplemented,	// 203: sys_sched_setaffinity pid_t pid,unsigned int len,unsigned long *user_mask_ptr
    &LinuxKernel::sys_notimplemented,	// 204: sys_sched_getaffinity pid_t pid,unsigned int len,unsigned long *user_mask_ptr
    &LinuxKernel::sys_notimplemented,	// 205: sys_set_thread_area NOT IMPLEMENTED. Use arch_prctl
    &LinuxKernel::sys_notimplemented,	// 206: sys_io_setup unsigned nr_events,aio_context_t *ctxp
    &LinuxKernel::sys_notimplemented,	// 207: sys_io_destroy aio_context_t ctx
    &LinuxKernel::sys_notimplemented,	// 208: sys_io_getevents aio_context_t ctx_id,long min_nr,long nr,struct io_event *events
    &LinuxKernel::sys_notimplemented,	// 209: sys_io_submit aio_context_t ctx_id,long nr,struct iocb **iocbpp
    &LinuxKernel::sys_notimplemented,	// 210: sys_io_cancel aio_context_t ctx_id,struct iocb *iocb,struct io_event *result
    &LinuxKernel::sys_notimplemented,	// 211: sys_get_thread_area NOT IMPLEMENTED. Use arch_prctl
    &LinuxKernel::sys_notimplemented,	// 212: sys_lookup_dcookie u64 cookie64,long buf,long len
    &LinuxKernel::sys_notimplemented,	// 213: sys_epoll_create int size
    &LinuxKernel::sys_notimplemented,	// 214: sys_epoll_ctl_old NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 215: sys_epoll_wait_old NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 216: sys_remap_file_pages unsigned long start,unsigned long size,unsigned long prot,unsigned long pgoff,unsigned long flags
    &LinuxKernel::sys_notimplemented,	// 217: sys_getdents64 unsigned int fd,struct linux_dirent64 *dirent,unsigned int count
    &LinuxKernel::sys_set_tid_address,	// 218: sys_set_tid_address int *tidptr
    &LinuxKernel::sys_notimplemented,	// 219: sys_restart_syscall 
    &LinuxKernel::sys_notimplemented,	// 220: sys_semtimedop int semid,struct sembuf *tsops,unsigned nsops,const struct timespec *timeout
    &LinuxKernel::sys_fadvise64,	// 221: sys_fadvise64 int fd,loff_t offset,size_t len,int advice
    &LinuxKernel::sys_notimplemented,	// 222: sys_timer_create const clockid_t which_clock,struct sigevent *timer_event_spec,timer_t *created_timer_id
    &LinuxKernel::sys_notimplemented,	// 223: sys_timer_settime timer_t timer_id,int flags,const struct itimerspec *new_setting,struct itimerspec *old_setting
    &LinuxKernel::sys_notimplemented,	// 224: sys_timer_gettime timer_t timer_id,struct itimerspec *setting
    &LinuxKernel::sys_notimplemented,	// 225: sys_timer_getoverrun timer_t timer_id
    &LinuxKernel::sys_notimplemented,	// 226: sys_timer_delete timer_t timer_id
    &LinuxKernel::sys_notimplemented,	// 227: sys_clock_settime const clockid_t which_clock,const struct timespec *tp
    &LinuxKernel::sys_clock_gettime,	// 228: sys_clock_gettime const clockid_t which_clock,struct timespec *tp
    &LinuxKernel::sys_notimplemented,	// 229: sys_clock_getres const clockid_t which_clock,struct timespec *tp
    &LinuxKernel::sys_notimplemented,	// 230: sys_clock_nanosleep const clockid_t which_clock,int flags,const struct timespec *rqtp,struct timespec *rmtp
    &LinuxKernel::sys_exit_group,	// 231: sys_exit_group int error_code
    &LinuxKernel::sys_notimplemented,	// 232: sys_epoll_wait int epfd,struct epoll_event *events,int maxevents,int timeout
    &LinuxKernel::sys_notimplemented,	// 233: sys_epoll_ctl int epfd,int op,int fd,struct epoll_event *event
    &LinuxKernel::sys_tgkill,	// 234: sys_tgkill pid_t tgid,pid_t pid,int sig
    &LinuxKernel::sys_notimplemented,	// 235: sys_utimes char *filename,struct timeval *utimes
    &LinuxKernel::sys_notimplemented,	// 236: sys_vserver NOT IMPLEMENTED
    &LinuxKernel::sys_notimplemented,	// 237: sys_mbind unsigned long start,unsigned long len,unsigned long mode,unsigned long *nmask,unsigned long maxnode,unsigned flags
    &LinuxKernel::sys_notimplemented,	// 238: sys_set_mempolicy int mode,unsigned long *nmask,unsigned long maxnode
    &LinuxKernel::sys_notimplemented,	// 239: sys_get_mempolicy int *policy,unsigned long *nmask,unsigned long maxnode,unsigned long addr,unsigned long flags
    &LinuxKernel::sys_notimplemented,	// 240: sys_mq_open const char *u_name,int oflag,mode_t mode,struct mq_attr *u_attr
    &LinuxKernel::sys_notimplemented,	// 241: sys_mq_unlink const char *u_name
    &LinuxKernel::sys_notimplemented,	// 242: sys_mq_timedsend mqd_t mqdes,const char *u_msg_ptr,size_t msg_len,unsigned int msg_prio,const stuct timespec *u_abs_timeout
    &LinuxKernel::sys_notimplemented,	// 243: sys_mq_timedreceive mqd_t mqdes,char *u_msg_ptr,size_t msg_len,unsigned int *u_msg_prio,const struct timespec *u_abs_timeout
    &LinuxKernel::sys_notimplemented,	// 244: sys_mq_notify mqd_t mqdes,const struct sigevent *u_notification
    &LinuxKernel::sys_notimplemented,	// 245: sys_mq_getsetattr mqd_t mqdes,const struct mq_attr *u_mqstat,struct mq_attr *u_omqstat
    &LinuxKernel::sys_notimplemented,	// 246: sys_kexec_load unsigned long entry,unsigned long nr_segments,struct kexec_segment *segments,unsigned long flags
    &LinuxKernel::sys_notimplemented,	// 247: sys_waitid int which,pid_t upid,struct siginfo *infop,int options,struct rusage *ru
    &LinuxKernel::sys_notimplemented,	// 248: sys_add_key const char *_type,const char *_description,const void *_payload,size_t plen
    &LinuxKernel::sys_notimplemented,	// 249: sys_request_key const char *_type,const char *_description,const char *_callout_info,key_serial_t destringid
    &LinuxKernel::sys_notimplemented,	// 250: sys_keyctl int option,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5
    &LinuxKernel::sys_notimplemented,	// 251: sys_ioprio_set int which,int who,int ioprio
    &LinuxKernel::sys_notimplemented,	// 252: sys_ioprio_get int which,int who
    &LinuxKernel::sys_notimplemented,	// 253: sys_inotify_init 
    &LinuxKernel::sys_notimplemented,	// 254: sys_inotify_add_watch int fd,const char *pathname,u32 mask
    &LinuxKernel::sys_notimplemented,	// 255: sys_inotify_rm_watch int fd,__s32 wd
    &LinuxKernel::sys_notimplemented,	// 256: sys_migrate_pages pid_t pid,unsigned long maxnode,const unsigned long *old_nodes,const unsigned long *new_nodes
    &LinuxKernel::sys_openat,	// 257: sys_openat int dfd,const char *filename,int flags,int mode
    &LinuxKernel::sys_notimplemented,	// 258: sys_mkdirat int dfd,const char *pathname,int mode
    &LinuxKernel::sys_notimplemented,	// 259: sys_mknodat int dfd,const char *filename,int mode,unsigned dev
    &LinuxKernel::sys_notimplemented,	// 260: sys_fchownat int dfd,const char *filename,uid_t user,gid_t group,int flag
    &LinuxKernel::sys_notimplemented,	// 261: sys_futimesat int dfd,const char *filename,struct timeval *utimes
    &LinuxKernel::sys_notimplemented,	// 262: sys_newfstatat int dfd,const char *filename,struct stat *statbuf,int flag
    &LinuxKernel::sys_notimplemented,	// 263: sys_unlinkat int dfd,const char *pathname,int flag
    &LinuxKernel::sys_notimplemented,	// 264: sys_renameat int oldfd,const char *oldname,int newfd,const char *newname
    &LinuxKernel::sys_notimplemented,	// 265: sys_linkat int oldfd,const char *oldname,int newfd,const char *newname,int flags
    &LinuxKernel::sys_notimplemented,	// 266: sys_symlinkat const char *oldname,int newfd,const char *newname
    &LinuxKernel::sys_notimplemented,	// 267: sys_readlinkat int dfd,const char *pathname,char *buf,int bufsiz
    &LinuxKernel::sys_notimplemented,	// 268: sys_fchmodat int dfd,const char *filename,mode_t mode
    &LinuxKernel::sys_notimplemented,	// 269: sys_faccessat int dfd,const char *filename,int mode
    &LinuxKernel::sys_notimplemented,	// 270: sys_pselect6 int n,fd_set *inp,fd_set *outp,fd_set *exp,struct timespec *tsp,void *sig
    &LinuxKernel::sys_notimplemented,	// 271: sys_ppoll struct pollfd *ufds,unsigned int nfds,struct timespec *tsp,const sigset_t *sigmask,size_t sigsetsize
    &LinuxKernel::sys_notimplemented,	// 272: sys_unshare unsigned long unshare_flags
    &LinuxKernel::sys_notimplemented,	// 273: sys_set_robust_list struct robust_list_head *head,size_t len
    &LinuxKernel::sys_notimplemented,	// 274: sys_get_robust_list int pid,struct robust_list_head **head_ptr,size_t *len_ptr
    &LinuxKernel::sys_notimplemented,	// 275: sys_splice int fd_in,loff_t *off_in,int fd_out,loff_t *off_out,size_t len,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 276: sys_tee int fdin,int fdout,size_t len,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 277: sys_sync_file_range long fd,loff_t offset,loff_t bytes,long flags
    &LinuxKernel::sys_notimplemented,	// 278: sys_vmsplice int fd,const struct iovec *iov,unsigned long nr_segs,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 279: sys_move_pages pid_t pid,unsigned long nr_pages,const void **pages,const int *nodes,int *status,int flags
    &LinuxKernel::sys_notimplemented,	// 280: sys_utimensat int dfd,const char *filename,struct timespec *utimes,int flags
    &LinuxKernel::sys_notimplemented,	// 281: sys_epoll_pwait int epfd,struct epoll_event *events,int maxevents,int timeout,const sigset_t *sigmask,size_t sigsetsize
    &LinuxKernel::sys_notimplemented,	// 282: sys_signalfd int ufd,sigset_t *user_mask,size_t sizemask
    &LinuxKernel::sys_notimplemented,	// 283: sys_timerfd_create int clockid,int flags
    &LinuxKernel::sys_notimplemented,	// 284: sys_eventfd unsigned int count
    &LinuxKernel::sys_notimplemented,	// 285: sys_fallocate long fd,long mode,loff_t offset,loff_t len
    &LinuxKernel::sys_notimplemented,	// 286: sys_timerfd_settime int ufd,int flags,const struct itimerspec *utmr,struct itimerspec *otmr
    &LinuxKernel::sys_notimplemented,	// 287: sys_timerfd_gettime int ufd,struct itimerspec *otmr
    &LinuxKernel::sys_notimplemented,	// 288: sys_accept4 int fd,struct sockaddr *upeer_sockaddr,int *upeer_addrlen,int flags
    &LinuxKernel::sys_notimplemented,	// 289: sys_signalfd4 int ufd,sigset_t *user_mask,size_t sizemask,int flags
    &LinuxKernel::sys_notimplemented,	// 290: sys_eventfd2 unsigned int count,int flags
    &LinuxKernel::sys_notimplemented,	// 291: sys_epoll_create1 int flags
    &LinuxKernel::sys_notimplemented,	// 292: sys_dup3 unsigned int oldfd,unsigned int newfd,int flags
    &LinuxKernel::sys_notimplemented,	// 293: sys_pipe2 int *filedes,int flags
    &LinuxKernel::sys_notimplemented,	// 294: sys_inotify_init1 int flags
    &LinuxKernel::sys_notimplemented,	// 295: sys_preadv unsigned long fd,const struct iovec *vec,unsigned long vlen,unsigned long pos_l,unsigned long pos_h
    &LinuxKernel::sys_notimplemented,	// 296: sys_pwritev unsigned long fd,const struct iovec *vec,unsigned long vlen,unsigned long pos_l,unsigned long pos_h
    &LinuxKernel::sys_notimplemented,	// 297: sys_rt_tgsigqueueinfo pid_t tgid,pid_t pid,int sig,siginfo_t *uinfo
    &LinuxKernel::sys_notimplemented,	// 298: sys_perf_event_open struct perf_event_attr *attr_uptr,pid_t pid,int cpu,int group_fd,unsigned long flags
    &LinuxKernel::sys_notimplemented,	// 299: sys_recvmmsg int fd,struct msghdr *mmsg,unsigned int vlen,unsigned int flags,struct timespec *timeout
    &LinuxKernel::sys_notimplemented,	// 300: sys_fanotify_init unsigned int flags,unsigned int event_f_flags
    &LinuxKernel::sys_notimplemented,	// 301: sys_fanotify_mark long fanotify_fd,long flags,__u64 mask,long dfd,long pathname
    &LinuxKernel::sys_notimplemented,	// 302: sys_prlimit64 pid_t pid,unsigned int resource,const struct rlimit64 *new_rlim,struct rlimit64 *old_rlim
    &LinuxKernel::sys_notimplemented,	// 303: sys_name_to_handle_at int dfd,const char *name,struct file_handle *handle,int *mnt_id,int flag
    &LinuxKernel::sys_notimplemented,	// 304: sys_open_by_handle_at int dfd,const char *name,struct file_handle *handle,int *mnt_id,int flags
    &LinuxKernel::sys_notimplemented,	// 305: sys_clock_adjtime clockid_t which_clock,struct timex *tx
    &LinuxKernel::sys_notimplemented,	// 306: sys_syncfs int fd
    &LinuxKernel::sys_notimplemented,	// 307: sys_sendmmsg int fd,struct mmsghdr *mmsg,unsigned int vlen,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 308: sys_setns int fd,int nstype
    &LinuxKernel::sys_notimplemented,	// 309: sys_getcpu unsigned *cpup,unsigned *nodep,struct getcpu_cache *unused
    &LinuxKernel::sys_notimplemented,	// 310: sys_process_vm_readv pid_t pid,const struct iovec *lvec,unsigned long liovcnt,const struct iovec *rvec,unsigned long riovcnt,unsigned long flags
    &LinuxKernel::sys_notimplemented,	// 311: sys_process_vm_writev pid_t pid,const struct iovec *lvec,unsigned long liovcnt,const struct iovcc *rvec,unsigned long riovcnt,unsigned long flags
    &LinuxKernel::sys_notimplemented,	// 312: sys_kcmp pid_t pid1,pid_t pid2,int type,unsigned long idx1,unsigned long idx2
    &LinuxKernel::sys_notimplemented,	// 313: sys_finit_module int fd,const char __user *uargs,int flags
    &LinuxKernel::sys_notimplemented,	// 314: sys_sched_setattr pid_t pid,struct sched_attr __user *attr,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 315: sys_sched_getattr pid_t pid,struct sched_attr __user *attr,unsigned int size,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 316: sys_renameat2 int olddfd,const char __user *oldname,int newdfd,const char __user *newname,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 317: sys_seccomp unsigned int op,unsigned int flags,const char __user *uargs
    &LinuxKernel::sys_notimplemented,	// 318: sys_getrandom char __user *buf,size_t count,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 319: sys_memfd_create const char __user *uname_ptr,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 320: sys_kexec_file_load int kernel_fd,int initrd_fd,unsigned long cmdline_len,const char __user *cmdline_ptr,unsigned long flags
    &LinuxKernel::sys_notimplemented,	// 321: sys_bpf int cmd,union bpf_attr *attr,unsigned int size
    &LinuxKernel::sys_notimplemented,	// 322: stub_execveat int dfd,const char __user *filename,const char __user *const __user *argv,const char __user *const __user *envp,int flags
    &LinuxKernel::sys_notimplemented,	// 323: userfaultfd int flags
    &LinuxKernel::sys_notimplemented,	// 324: membarrier int cmd,int flags
    &LinuxKernel::sys_notimplemented,	// 325: mlock2 unsigned long start,size_t len,int flags
    &LinuxKernel::sys_notimplemented,	// 326: copy_file_range int fd_in,loff_t __user *off_in,int fd_out,loff_t __user * off_out,size_t len,unsigned int flags
    &LinuxKernel::sys_notimplemented,	// 327: preadv2 unsigned long fd,const struct iovec __user *vec,unsigned long vlen,unsigned long pos_l,unsigned long pos_h,int flags
    &LinuxKernel::sys_notimplemented,	// 328: pwritev2 unsigned long fd,const struct iovec __user *vec,unsigned long vlen,unsigned long pos_l,unsigned long pos_h,int flags
