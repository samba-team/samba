#include "bsd_locl.h"

#include <termios.h>

/* HP-UX 9.0 termios doesn't define these */
#ifndef FLUSHO
#define	FLUSHO	0
#endif

#ifndef XTABS
#define	XTABS	0
#endif

#ifndef OXTABS
#define OXTABS	XTABS
#endif

/* Ultrix... */
#ifndef ECHOPRT
#define ECHOPRT	0
#endif

#ifndef ECHOCTL
#define ECHOCTL	0
#endif

#ifndef ECHOKE
#define ECHOKE	0
#endif

#ifndef IMAXBEL
#define IMAXBEL	0
#endif

#define Ctl(x) ((x) ^ 0100)

void
stty_default(void)
{
    struct	termios termios;

    /*
     * Finalize the terminal settings. Some systems default to 8 bits,
     * others to 7, so we should leave that alone.
     */
    tcgetattr(0, &termios);

    termios.c_iflag |= (BRKINT|IGNPAR|ICRNL|IXON|IMAXBEL);
    termios.c_iflag &= ~IXANY;

    termios.c_lflag |= (ISIG|IEXTEN|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE);
    termios.c_lflag &= ~(ECHOPRT|TOSTOP|FLUSHO);

    termios.c_oflag |= (OPOST|ONLCR);
    termios.c_oflag &= ~OXTABS;

    termios.c_cc[VINTR] = Ctl('C');
    termios.c_cc[VERASE] = Ctl('H');
    termios.c_cc[VKILL] = Ctl('U');
    termios.c_cc[VEOF] = Ctl('D');

    termios.c_cc[VSUSP] = Ctl('Z');
    
    (void)tcsetattr(0, TCSANOW, &termios);
}
