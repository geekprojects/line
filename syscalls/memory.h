#ifndef __LINE_SYSCALLS_MEMORY_H_
#define __LINE_SYSCALLS_MEMORY_H_

#define LINUX_MAP_SHARED      0x01            /* Share changes */
#define LINUX_MAP_PRIVATE     0x02            /* Changes are private */
#define LINUX_MAP_TYPE        0x0f            /* Mask for type of mapping */
#define LINUX_MAP_FIXED       0x10            /* Interpret addr exactly */
#define LINUX_MAP_ANONYMOUS   0x20            /* don't use a file */
#define LINUX_MAP_NORESERVE   0x4000          /* don't check for reservations */

#endif
