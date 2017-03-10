#ifndef __LINUX_TERM_H_
#define __LINUX_TERM_H_

#define LINUX_TCGETS          0x5401
#define LINUX_TIOCGPGRP       0x540F
#define LINUX_TIOCSPGRP       0x5410
#define LINUX_TIOCGWINSZ      0x5413
#define LINUX_TIOCSWINSZ    0x5414
#define LINUX_TCSETSW        0x5403

struct linux_vt_mode {
        char mode;              /* vt mode */
        char waitv;             /* if set, hang on writes if not active */
        short relsig;           /* signal to raise on release req */
        short acqsig;           /* signal to raise on acquisition */
        short frsig;            /* unused (set to 0) */
};
#define LINUX_VT_GETMODE      0x5601  /* get mode of active vt */
#define LINUX_VT_SETMODE      0x5602  /* set mode of active vt */
#define         LINUX_VT_AUTO         0x00    /* auto vt switching */
#define         LINUX_VT_PROCESS      0x01    /* process controls switching */
#define         LINUX_VT_ACKACQ       0x02    /* acknowledge switch */

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
