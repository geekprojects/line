#ifndef __LINUX_TERM_H_
#define __LINUX_TERM_H_

#define LINUX_TCGETS          0x5401
#define LINUX_TIOCGPGRP       0x540F
#define LINUX_TIOCSPGRP       0x5410
#define LINUX_TIOCGWINSZ      0x5413

typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

#define NCCS 19
struct termios
{
    tcflag_t c_iflag;               /* input mode flags */
    tcflag_t c_oflag;               /* output mode flags */
    tcflag_t c_cflag;               /* control mode flags */
    tcflag_t c_lflag;               /* local mode flags */
    cc_t c_line;                    /* line discipline */
    cc_t c_cc[NCCS];                /* control characters */
};

struct linux_winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

#endif
