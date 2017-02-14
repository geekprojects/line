#ifndef __LINE_SYSCALLS_SYSTEM_H_
#define __LINE_SYSCALLS_SYSTEM_H_

#define LINUX_OLD_UTSNAME_LENGTH 65
struct  linux_oldutsname
{
    char sysname[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Name of OS */
    char nodename[LINUX_OLD_UTSNAME_LENGTH]; /* [XSI] Name of this network node */
    char release[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Release level */
    char version[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Version level */
    char machine[LINUX_OLD_UTSNAME_LENGTH];  /* [XSI] Hardware type */
};

#endif
