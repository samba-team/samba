/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>
#ifdef SOCKS
#include <socks.h>
#endif

RCSID("$Id$");

#include "telnetd.h"
#include "pathnames.h"

#ifdef AUTHENTICATION
#include <libtelnet/auth.h>
#endif

#if defined(CRAY) || (defined(__hpux) && !defined(HAVE_UTMPX_H))
# define PARENT_DOES_UTMP
#endif

#ifdef  NEWINIT
#error NEWINIT not supported
#endif

#ifdef HAVE_UTMPX
#include <utmpx.h>
struct	utmpx wtmp;
#else
#include <utmp.h>
struct	utmp wtmp;
#endif /* HAVE_UTMPX */

#ifdef HAVE_UT_HOST
int	utmp_len = sizeof(wtmp.ut_host);
#else
int	utmp_len = MaxHostNameLen;
#endif
#ifndef PARENT_DOES_UTMP
char	wtmpf[]	= "/usr/adm/wtmp";
char	utmpf[] = "/etc/utmp";
#else /* PARENT_DOES_UTMP */
char	wtmpf[]	= "/etc/wtmp";
#endif /* PARENT_DOES_UTMP */

#ifdef CRAY
#include <tmpdir.h>
#include <sys/wait.h>
#endif	/* CRAY */

#ifdef	STREAMSPTY

#ifdef HAVE_SAC_H
#include <sac.h>
#endif

#include <sys/stropts.h>
#endif

#define SCPYN(a, b)	strncpy(a, b, sizeof(a))
#define SCMPN(a, b)	strncmp(a, b, sizeof(a))

#ifdef	HAVE_SYS_STREAM_H
#ifdef  HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef __hpux
#undef SE
#endif
#include <sys/stream.h>
#endif
#if !(defined(__sgi) || defined(__linux) || defined(_AIX)) && defined(HAVE_SYS_TTY)
#include <sys/tty.h>
#endif
#ifdef	t_erase
#undef	t_erase
#undef	t_kill
#undef	t_intrc
#undef	t_quitc
#undef	t_startc
#undef	t_stopc
#undef	t_eofc
#undef	t_brkc
#undef	t_suspc
#undef	t_dsuspc
#undef	t_rprntc
#undef	t_flushc
#undef	t_werasc
#undef	t_lnextc
#endif

# ifndef	TCSANOW
#  ifdef TCSETS
#   define	TCSANOW		TCSETS
#   define	TCSADRAIN	TCSETSW
#   define	tcgetattr(f, t)	ioctl(f, TCGETS, (char *)t)
#  else
#   ifdef TCSETA
#    define	TCSANOW		TCSETA
#    define	TCSADRAIN	TCSETAW
#    define	tcgetattr(f, t)	ioctl(f, TCGETA, (char *)t)
#   else
#    define	TCSANOW		TIOCSETA
#    define	TCSADRAIN	TIOCSETAW
#    define	tcgetattr(f, t)	ioctl(f, TIOCGETA, (char *)t)
#   endif
#  endif
#  define	tcsetattr(f, a, t)	ioctl(f, a, t)
#  define	cfsetospeed(tp, val)	(tp)->c_cflag &= ~CBAUD; \
					(tp)->c_cflag |= (val)
#  define	cfgetospeed(tp)		((tp)->c_cflag & CBAUD)
#  ifdef CIBAUD
#   define	cfsetispeed(tp, val)	(tp)->c_cflag &= ~CIBAUD; \
					(tp)->c_cflag |= ((val)<<IBSHIFT)
#   define	cfgetispeed(tp)		(((tp)->c_cflag & CIBAUD)>>IBSHIFT)
#  else
#   define	cfsetispeed(tp, val)	(tp)->c_cflag &= ~CBAUD; \
					(tp)->c_cflag |= (val)
#   define	cfgetispeed(tp)		((tp)->c_cflag & CBAUD)
#  endif
# endif /* TCSANOW */
struct termios termbuf, termbuf2;	/* pty control structure */
# ifdef  STREAMSPTY
static int ttyfd = -1;
int really_stream = 0;
# endif

char *new_login = LOGIN_PATH;

/*
 * init_termbuf()
 * copy_termbuf(cp)
 * set_termbuf()
 *
 * These three routines are used to get and set the "termbuf" structure
 * to and from the kernel.  init_termbuf() gets the current settings.
 * copy_termbuf() hands in a new "termbuf" to write to the kernel, and
 * set_termbuf() writes the structure into the kernel.
 */

void
init_termbuf(void)
{
# ifdef  STREAMSPTY
	if (really_stream)
		tcgetattr(ttyfd, &termbuf);
	else
# endif
		tcgetattr(ourpty, &termbuf);
	termbuf2 = termbuf;
}

#if	defined(LINEMODE) && defined(TIOCPKT_IOCTL)
	void
copy_termbuf(cp, len)
	char *cp;
	int len;
{
	if (len > sizeof(termbuf))
		len = sizeof(termbuf);
	memmove(&termbuf, cp, len);
	termbuf2 = termbuf;
}
#endif	/* defined(LINEMODE) && defined(TIOCPKT_IOCTL) */

	void
set_termbuf(void)
{
	/*
	 * Only make the necessary changes.
	 */
	if (memcmp(&termbuf, &termbuf2, sizeof(termbuf)))
# ifdef  STREAMSPTY
		if (really_stream)
			tcsetattr(ttyfd, TCSANOW, &termbuf);
		else
# endif
			tcsetattr(ourpty, TCSANOW, &termbuf);
}


/*
 * spcset(func, valp, valpp)
 *
 * This function takes various special characters (func), and
 * sets *valp to the current value of that character, and
 * *valpp to point to where in the "termbuf" structure that
 * value is kept.
 *
 * It returns the SLC_ level of support for this function.
 */


	int
spcset(int func, cc_t *valp, cc_t **valpp)
{

#define	setval(a, b)	*valp = termbuf.c_cc[a]; \
			*valpp = &termbuf.c_cc[a]; \
			return(b);
#define	defval(a) *valp = ((cc_t)a); *valpp = (cc_t *)0; return(SLC_DEFAULT);

	switch(func) {
	case SLC_EOF:
		setval(VEOF, SLC_VARIABLE);
	case SLC_EC:
		setval(VERASE, SLC_VARIABLE);
	case SLC_EL:
		setval(VKILL, SLC_VARIABLE);
	case SLC_IP:
		setval(VINTR, SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
	case SLC_ABORT:
		setval(VQUIT, SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
	case SLC_XON:
#ifdef	VSTART
		setval(VSTART, SLC_VARIABLE);
#else
		defval(0x13);
#endif
	case SLC_XOFF:
#ifdef	VSTOP
		setval(VSTOP, SLC_VARIABLE);
#else
		defval(0x11);
#endif
	case SLC_EW:
#ifdef	VWERASE
		setval(VWERASE, SLC_VARIABLE);
#else
		defval(0);
#endif
	case SLC_RP:
#ifdef	VREPRINT
		setval(VREPRINT, SLC_VARIABLE);
#else
		defval(0);
#endif
	case SLC_LNEXT:
#ifdef	VLNEXT
		setval(VLNEXT, SLC_VARIABLE);
#else
		defval(0);
#endif
	case SLC_AO:
#if	!defined(VDISCARD) && defined(VFLUSHO)
# define VDISCARD VFLUSHO
#endif
#ifdef	VDISCARD
		setval(VDISCARD, SLC_VARIABLE|SLC_FLUSHOUT);
#else
		defval(0);
#endif
	case SLC_SUSP:
#ifdef	VSUSP
		setval(VSUSP, SLC_VARIABLE|SLC_FLUSHIN);
#else
		defval(0);
#endif
#ifdef	VEOL
	case SLC_FORW1:
		setval(VEOL, SLC_VARIABLE);
#endif
#ifdef	VEOL2
	case SLC_FORW2:
		setval(VEOL2, SLC_VARIABLE);
#endif
	case SLC_AYT:
#ifdef	VSTATUS
		setval(VSTATUS, SLC_VARIABLE);
#else
		defval(0);
#endif

	case SLC_BRK:
	case SLC_SYNCH:
	case SLC_EOR:
		defval(0);

	default:
		*valp = 0;
		*valpp = 0;
		return(SLC_NOSUPPORT);
	}
}

#ifdef CRAY
/*
 * getnpty()
 *
 * Return the number of pty's configured into the system.
 */
	int
getnpty()
{
#ifdef _SC_CRAY_NPTY
	int numptys;

	if ((numptys = sysconf(_SC_CRAY_NPTY)) != -1)
		return numptys;
	else
#endif /* _SC_CRAY_NPTY */
		return 128;
}
#endif /* CRAY */

/*
 * getpty()
 *
 * Allocate a pty.  As a side effect, the external character
 * array "line" contains the name of the slave side.
 *
 * Returns the file descriptor of the opened pty.
 */

static char Xline[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
char *line = Xline;

char *line_nodev;
char *line_notty;

#ifdef	CRAY
char *myline = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
#endif	/* CRAY */

#ifndef HAVE_PTSNAME
static char *ptsname(int fd)
{
#ifdef HAVE_TTYNAME
  return ttyname(fd);
#else
  return NULL;
#endif
}
#endif

#ifdef HAVE_UTMPX
static char utid[32]; /* XXX larger than ut_id */

void
set_utid(void)
{
    int ptynum;
    
    line_nodev = line;
    if(!strncmp(line, "/dev/", 5))
	line_nodev += 5;

    line_notty = line_nodev;
    if(!strncmp(line_nodev, "tty", 3))
	line_notty += 3;
    else if(!strncmp(line_nodev, "pts/", 4))
	line_notty += 4;
    
    /* Derive utmp ID from pty slave number */
    if(isdigit(line_notty[0]) && sscanf(line_notty, "%d", &ptynum) == 1)
	
	sprintf(utid, "tn%02x", ptynum & 0xff);
    else
	sprintf(utid, "tn%s", line_notty);
}
#else
void
set_utid(void)
{
}
#endif

int getpty(int *ptynum)
{
#ifdef __osf__ /* XXX */
        int master;
	int slave;
	if(openpty(&master, &slave, line, 0, 0) == 0){
	  close(slave);
	  return master;
	}
	return -1;
#else
#if IRIX == 4
	int master, slave;
	char *p;
	p = _getpty(&master, O_RDWR, 0600, 1);
	if(p == NULL)
	    return -1;
	strcpy(line, p);
	return master;
#else

        int p;
	char *cp, *p1, *p2;
	int i;
	int dummy;
#if 0 /* && defined(HAVE_OPENPTY) */
        int master;
	int slave;
	if(openpty(&master, &slave, line, 0, 0) == 0){
	  close(slave);
	  return master;
	}
#else
#ifdef	STREAMSPTY
	char *clone[] = { "/dev/ptc", "/dev/ptmx", "/dev/ptm", 
			  "/dev/ptym/clone", 0 };

	char **q;
	for(q=clone; *q; q++){
	  p=open(*q, O_RDWR);
	  if(p >= 0){
#ifdef HAVE_GRANTPT
	    grantpt(p);
#endif
#ifdef HAVE_UNLOCKPT
	    unlockpt(p);
#endif
	    strcpy(line, ptsname(p));
	    really_stream = 1;
	    return p;
	  }
	}
#endif /* STREAMSPTY */
#ifndef CRAY

#ifndef	__hpux
	sprintf(line, "/dev/ptyXX");
	p1 = &line[8];
	p2 = &line[9];
#else
	sprintf(line, "/dev/ptym/ptyXX");
	p1 = &line[13];
	p2 = &line[14];
#endif

	
	for (cp = "pqrstuvwxyzPQRST"; *cp; cp++) {
		struct stat stb;

		*p1 = *cp;
		*p2 = '0';
		/*
		 * This stat() check is just to keep us from
		 * looping through all 256 combinations if there
		 * aren't that many ptys available.
		 */
		if (stat(line, &stb) < 0)
			break;
		for (i = 0; i < 16; i++) {
			*p2 = "0123456789abcdef"[i];
			p = open(line, O_RDWR);
			if (p > 0) {
#ifndef	__hpux
				line[5] = 't';
#else
				for (p1 = &line[8]; *p1; p1++)
					*p1 = *(p1+1);
				line[9] = 't';
#endif
				chown(line, 0, 0);
				chmod(line, 0600);
#if SunOS == 4
				if (ioctl(p, TIOCGPGRP, &dummy) == 0
				    || errno != EIO) {
					chmod(line, 0666);
					close(p);
					line[5] = 'p';
				} else
#endif /* SunOS == 4 */
					return(p);
			}
		}
	}
#else	/* CRAY */
	extern lowpty, highpty;
	struct stat sb;

	for (*ptynum = lowpty; *ptynum <= highpty; (*ptynum)++) {
		sprintf(myline, "/dev/pty/%03d", *ptynum);
		p = open(myline, 2);
		if (p < 0)
			continue;
		sprintf(line, "/dev/ttyp%03d", *ptynum);
		/*
		 * Here are some shenanigans to make sure that there
		 * are no listeners lurking on the line.
		 */
		if(stat(line, &sb) < 0) {
			close(p);
			continue;
		}
		if(sb.st_uid || sb.st_gid || sb.st_mode != 0600) {
			chown(line, 0, 0);
			chmod(line, 0600);
			close(p);
			p = open(myline, 2);
			if (p < 0)
				continue;
		}
		/*
		 * Now it should be safe...check for accessability.
		 */
		if (access(line, 6) == 0)
			return(p);
		else {
			/* no tty side to pty so skip it */
			close(p);
		}
	}
#endif	/* CRAY */
#endif	/* STREAMSPTY */
#endif /* OPENPTY */
	return(-1);
#endif
}

#ifdef	LINEMODE
/*
 * tty_flowmode()	Find out if flow control is enabled or disabled.
 * tty_linemode()	Find out if linemode (external processing) is enabled.
 * tty_setlinemod(on)	Turn on/off linemode.
 * tty_isecho()		Find out if echoing is turned on.
 * tty_setecho(on)	Enable/disable character echoing.
 * tty_israw()		Find out if terminal is in RAW mode.
 * tty_binaryin(on)	Turn on/off BINARY on input.
 * tty_binaryout(on)	Turn on/off BINARY on output.
 * tty_isediting()	Find out if line editing is enabled.
 * tty_istrapsig()	Find out if signal trapping is enabled.
 * tty_setedit(on)	Turn on/off line editing.
 * tty_setsig(on)	Turn on/off signal trapping.
 * tty_issofttab()	Find out if tab expansion is enabled.
 * tty_setsofttab(on)	Turn on/off soft tab expansion.
 * tty_islitecho()	Find out if typed control chars are echoed literally
 * tty_setlitecho()	Turn on/off literal echo of control chars
 * tty_tspeed(val)	Set transmit speed to val.
 * tty_rspeed(val)	Set receive speed to val.
 */


	int
tty_linemode()
{
	return(termbuf.c_lflag & EXTPROC);
}

	void
tty_setlinemode(on)
	int on;
{
#ifdef	TIOCEXT
	set_termbuf();
	ioctl(ourpty, TIOCEXT, (char *)&on);
	init_termbuf();
#else	/* !TIOCEXT */
# ifdef	EXTPROC
	if (on)
		termbuf.c_lflag |= EXTPROC;
	else
		termbuf.c_lflag &= ~EXTPROC;
# endif
#endif	/* TIOCEXT */
}
#endif	/* LINEMODE */

	int
tty_isecho(void)
{
	return (termbuf.c_lflag & ECHO);
}

	int
tty_flowmode(void)
{
	return((termbuf.c_iflag & IXON) ? 1 : 0);
}

	int
tty_restartany(void)
{
	return((termbuf.c_iflag & IXANY) ? 1 : 0);
}

	void
tty_setecho(int on)
{
	if (on)
		termbuf.c_lflag |= ECHO;
	else
		termbuf.c_lflag &= ~ECHO;
}

	int
tty_israw(void)
{
	return(!(termbuf.c_lflag & ICANON));
}

#if	defined (AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	int
tty_setraw(on)
{
	if (on)
		termbuf.c_lflag &= ~ICANON;
	else
		termbuf.c_lflag |= ICANON;
}
#endif

	void
tty_binaryin(int on)
{
	if (on) {
		termbuf.c_iflag &= ~ISTRIP;
	} else {
		termbuf.c_iflag |= ISTRIP;
	}
}

	void
tty_binaryout(int on)
{
	if (on) {
		termbuf.c_cflag &= ~(CSIZE|PARENB);
		termbuf.c_cflag |= CS8;
		termbuf.c_oflag &= ~OPOST;
	} else {
		termbuf.c_cflag &= ~CSIZE;
		termbuf.c_cflag |= CS7|PARENB;
		termbuf.c_oflag |= OPOST;
	}
}

	int
tty_isbinaryin(void)
{
	return(!(termbuf.c_iflag & ISTRIP));
}

	int
tty_isbinaryout(void)
{
	return(!(termbuf.c_oflag&OPOST));
}

#ifdef	LINEMODE
	int
tty_isediting()
{
	return(termbuf.c_lflag & ICANON);
}

	int
tty_istrapsig()
{
	return(termbuf.c_lflag & ISIG);
}

	void
tty_setedit(on)
	int on;
{
	if (on)
		termbuf.c_lflag |= ICANON;
	else
		termbuf.c_lflag &= ~ICANON;
}

	void
tty_setsig(on)
	int on;
{
	if (on)
		termbuf.c_lflag |= ISIG;
	else
		termbuf.c_lflag &= ~ISIG;
}
#endif	/* LINEMODE */

	int
tty_issofttab(void)
{
# ifdef	OXTABS
	return (termbuf.c_oflag & OXTABS);
# endif
# ifdef	TABDLY
	return ((termbuf.c_oflag & TABDLY) == TAB3);
# endif
}

	void
tty_setsofttab(int on)
{
	if (on) {
# ifdef	OXTABS
		termbuf.c_oflag |= OXTABS;
# endif
# ifdef	TABDLY
		termbuf.c_oflag &= ~TABDLY;
		termbuf.c_oflag |= TAB3;
# endif
	} else {
# ifdef	OXTABS
		termbuf.c_oflag &= ~OXTABS;
# endif
# ifdef	TABDLY
		termbuf.c_oflag &= ~TABDLY;
		termbuf.c_oflag |= TAB0;
# endif
	}
}

	int
tty_islitecho(void)
{
# ifdef	ECHOCTL
	return (!(termbuf.c_lflag & ECHOCTL));
# endif
# ifdef	TCTLECH
	return (!(termbuf.c_lflag & TCTLECH));
# endif
# if	!defined(ECHOCTL) && !defined(TCTLECH)
	return (0);	/* assumes ctl chars are echoed '^x' */
# endif
}

	void
tty_setlitecho(int on)
{
# ifdef	ECHOCTL
	if (on)
		termbuf.c_lflag &= ~ECHOCTL;
	else
		termbuf.c_lflag |= ECHOCTL;
# endif
# ifdef	TCTLECH
	if (on)
		termbuf.c_lflag &= ~TCTLECH;
	else
		termbuf.c_lflag |= TCTLECH;
# endif
}

	int
tty_iscrnl(void)
{
	return (termbuf.c_iflag & ICRNL);
}

/*
 * Try to guess whether speeds are "encoded" (4.2BSD) or just numeric (4.4BSD).
 */
#if B4800 != 4800
#define	DECODE_BAUD
#endif

#ifdef	DECODE_BAUD

/*
 * A table of available terminal speeds
 */
struct termspeeds {
	int	speed;
	int	value;
} termspeeds[] = {
	{ 0,      B0 },      { 50,    B50 },    { 75,     B75 },
	{ 110,    B110 },    { 134,   B134 },   { 150,    B150 },
	{ 200,    B200 },    { 300,   B300 },   { 600,    B600 },
	{ 1200,   B1200 },   { 1800,  B1800 },  { 2400,   B2400 },
	{ 4800,   B4800 },
#ifdef	B7200
	{ 7200,  B7200 },
#endif
	{ 9600,   B9600 },
#ifdef	B14400
	{ 14400,  B14400 },
#endif
#ifdef	B19200
	{ 19200,  B19200 },
#endif
#ifdef	B28800
	{ 28800,  B28800 },
#endif
#ifdef	B38400
	{ 38400,  B38400 },
#endif
#ifdef	B57600
	{ 57600,  B57600 },
#endif
#ifdef	B115200
	{ 115200, B115200 },
#endif
#ifdef	B230400
	{ 230400, B230400 },
#endif
	{ -1,     0 }
};
#endif	/* DECODE_BUAD */

	void
tty_tspeed(int val)
{
#ifdef	DECODE_BAUD
	struct termspeeds *tp;

	for (tp = termspeeds; (tp->speed != -1) && (val > tp->speed); tp++)
		;
	if (tp->speed == -1)	/* back up to last valid value */
		--tp;
	cfsetospeed(&termbuf, tp->value);
#else	/* DECODE_BUAD */
	cfsetospeed(&termbuf, val);
#endif	/* DECODE_BUAD */
}

	void
tty_rspeed(int val)
{
#ifdef	DECODE_BAUD
	struct termspeeds *tp;

	for (tp = termspeeds; (tp->speed != -1) && (val > tp->speed); tp++)
		;
	if (tp->speed == -1)	/* back up to last valid value */
		--tp;
	cfsetispeed(&termbuf, tp->value);
#else	/* DECODE_BAUD */
	cfsetispeed(&termbuf, val);
#endif	/* DECODE_BAUD */
}

#ifdef PARENT_DOES_UTMP
extern	struct utmp wtmp;
extern char wtmpf[];

extern void utmp_sig_init P((void));
extern void utmp_sig_reset P((void));
extern void utmp_sig_wait P((void));
extern void utmp_sig_notify P((int));
# endif /* PARENT_DOES_UTMP */

#ifdef STREAMSPTY

/* I_FIND seems to live a life of its own */
static int my_find(int fd, char *module)
{
#if defined(I_FIND) && defined(I_LIST)
  static int flag;
  static struct str_list sl;
  int n;
  int i;
  
  if(!flag){
    n = ioctl(fd, I_LIST, 0);
    if(n < 0){
      perror("ioctl(fd, I_LIST, 0)");
      return -1;
    }
    sl.sl_modlist=(struct str_mlist*)malloc(n * sizeof(struct str_mlist));
    sl.sl_nmods = n;
    n = ioctl(fd, I_LIST, &sl);
    if(n < 0){
      perror("ioctl(fd, I_LIST, n)");
      return -1;
    }
    flag = 1;
  }
  
  for(i=0; i<sl.sl_nmods; i++)
    if(!strcmp(sl.sl_modlist[i].l_name, module))
      return 1;
#endif
  return 0;
}

static void maybe_push_modules(int fd, char **modules)
{
  char **p;
  int err;

  for(p=modules; *p; p++){
    err = my_find(fd, *p);
    if(err == 1)
      break;
    if(err < 0 && errno != EINVAL)
      fatalperror(net, "my_find()");
    /* module not pushed or does not exist */
  }
  /* p points to null or to an already pushed module, now push all
     modules before this one */
  
  for(p--; p >= modules; p--){
    err = ioctl(fd, I_PUSH, *p);
    if(err < 0 && errno != EINVAL)
      fatalperror(net, "I_PUSH");
  }
}
#endif

/*
 * getptyslave()
 *
 * Open the slave side of the pty, and do any initialization
 * that is necessary.  The return value is a file descriptor
 * for the slave side.
 */
void getptyslave(void)
{
	int t = -1;

# ifdef	LINEMODE
	int waslm;
# endif
# ifdef	TIOCGWINSZ
	struct winsize ws;
	extern int def_row, def_col;
# endif
	extern int def_tspeed, def_rspeed;
	/*
	 * Opening the slave side may cause initilization of the
	 * kernel tty structure.  We need remember the state of
	 * 	if linemode was turned on
	 *	terminal window size
	 *	terminal speed
	 * so that we can re-set them if we need to.
	 */
# ifdef	LINEMODE
	waslm = tty_linemode();
# endif


	/*
	 * Make sure that we don't have a controlling tty, and
	 * that we are the session (process group) leader.
	 */

#ifdef HAVE_SETSID
	if(setsid()<0)
	  fatalperror(net, "setsid()");
#else
# ifdef	TIOCNOTTY
	t = open(_PATH_TTY, O_RDWR);
	if (t >= 0) {
		ioctl(t, TIOCNOTTY, (char *)0);
		close(t);
	}
# endif
#endif

# ifdef PARENT_DOES_UTMP
	/*
	 * Wait for our parent to get the utmp stuff to get done.
	 */
	utmp_sig_wait();
# endif

	t = cleanopen(line);
	if (t < 0)
		fatalperror(net, line);

#ifdef  STREAMSPTY
	ttyfd = t;
	  

	/*
	 * Not all systems have (or need) modules ttcompat and pckt so
	 * don't flag it as a fatal error if they don't exist.
	 */

	if (really_stream)
	{
	  /* these are the streams modules that we want pushed. note
	     that they are in reverse order, ptem will be pushed
	     first. maybe_push_modules() will try to push all modules
	     before the first one that isn't already pushed. i.e if
	     ldterm is pushed, only ttcompat will be attempted.

	     all this is because we don't know which modules are
	     available, and we don't know which modules are already
	     pushed (via autopush, for instance).

	     */
	     
	  char *ttymodules[] = { "ttcompat", "ldterm", "ptem", NULL };
	  char *ptymodules[] = { "pckt", NULL };

	  maybe_push_modules(t, ttymodules);
	  maybe_push_modules(ourpty, ptymodules);
	}
#endif
	/*
	 * set up the tty modes as we like them to be.
	 */
	init_termbuf();
# ifdef	TIOCGWINSZ
	if (def_row || def_col) {
		memset(&ws, 0, sizeof(ws));
		ws.ws_col = def_col;
		ws.ws_row = def_row;
		ioctl(t, TIOCSWINSZ, (char *)&ws);
	}
# endif

	/*
	 * Settings for sgtty based systems
	 */

	/*
	 * Settings for UNICOS (and HPUX)
	 */
# if defined(CRAY) || defined(__hpux)
	termbuf.c_oflag = OPOST|ONLCR|TAB3;
	termbuf.c_iflag = IGNPAR|ISTRIP|ICRNL|IXON;
	termbuf.c_lflag = ISIG|ICANON|ECHO|ECHOE|ECHOK;
	termbuf.c_cflag = EXTB|HUPCL|CS8;
# endif

	/*
	 * Settings for all other termios/termio based
	 * systems, other than 4.4BSD.  In 4.4BSD the
	 * kernel does the initial terminal setup.
	 */
# if !(defined(CRAY) || defined(__hpux)) && (BSD <= 43)
#  ifndef	OXTABS
#   define OXTABS	0
#  endif
	termbuf.c_lflag |= ECHO;
	termbuf.c_oflag |= ONLCR|OXTABS;
	termbuf.c_iflag |= ICRNL;
	termbuf.c_iflag &= ~IXOFF;
# endif
	tty_rspeed((def_rspeed > 0) ? def_rspeed : 9600);
	tty_tspeed((def_tspeed > 0) ? def_tspeed : 9600);
# ifdef	LINEMODE
	if (waslm)
		tty_setlinemode(1);
# endif	/* LINEMODE */

	/*
	 * Set the tty modes, and make this our controlling tty.
	 */
	set_termbuf();
	if (login_tty(t) == -1)
		fatalperror(net, "login_tty");
	if (net > 2)
		close(net);
#if	defined(AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	/*
	 * Leave the pty open so that we can write out the rlogin
	 * protocol for /bin/login, if the authentication works.
	 */
#else
	if (ourpty > 2) {
		close(ourpty);
		ourpty = -1;
	}
#endif
}

#ifndef	O_NOCTTY
#define	O_NOCTTY	0
#endif
/*
 * Open the specified slave side of the pty,
 * making sure that we have a clean tty.
 */

int cleanopen(char *line)
{
	int t;

#ifdef STREAMSPTY
	if (!really_stream)
#endif
	{
		/*
		 * Make sure that other people can't open the
		 * slave side of the connection.
		 */
		chown(line, 0, 0);
		chmod(line, 0600);
	}

# if !defined(CRAY) && (BSD > 43)
	revoke(line);
# endif

	t = open(line, O_RDWR|O_NOCTTY);

	if (t < 0)
		return(-1);

	/*
	 * Hangup anybody else using this ttyp, then reopen it for
	 * ourselves.
	 */
# if !(defined(CRAY) || defined(__hpux)) && (BSD <= 43) && !defined(STREAMSPTY)
	signal(SIGHUP, SIG_IGN);
#ifdef HAVE_VHANGUP
	vhangup();
#else
#endif
	signal(SIGHUP, SIG_DFL);
	t = open(line, O_RDWR|O_NOCTTY);
	if (t < 0)
		return(-1);
# endif
# if	defined(CRAY) && defined(TCVHUP)
	{
		int i;
		signal(SIGHUP, SIG_IGN);
		ioctl(t, TCVHUP, (char *)0);
		signal(SIGHUP, SIG_DFL);

		i = open(line, O_RDWR);

		if (i < 0)
			return(-1);
		close(t);
		t = i;
	}
# endif	/* defined(CRAY) && defined(TCVHUP) */
	return(t);
}

#if !defined(BSD4_4)

int login_tty(int t)
{
#if 0 /* setsid done in other place */
#if defined(HAVE_SETSID) && !defined(_AIX)
	if (setsid() < 0) {
#ifdef ultrix
		/*
		 * The setsid() may have failed because we
		 * already have a pgrp == pid.  Zero out
		 * our pgrp and try again...
		 */
		if ((setpgrp(0, 0) < 0) || (setsid() < 0))
#endif
			fatalperror(net, "setsid()");
	}
#endif /* HAVE_SETSID */
#endif
# if defined(TIOCSCTTY) && !defined(__hpux)
	if (ioctl(t, TIOCSCTTY, (char *)0) < 0)
		fatalperror(net, "ioctl(sctty)");
#  if defined(CRAY)
	/*
	 * Close the hard fd to /dev/ttypXXX, and re-open through
	 * the indirect /dev/tty interface.
	 */
	close(t);
	if ((t = open("/dev/tty", O_RDWR)) < 0)
		fatalperror(net, "open(/dev/tty)");
#  endif
# else
	/*
	 * We get our controlling tty assigned as a side-effect
	 * of opening up a tty device.  But on BSD based systems,
	 * this only happens if our process group is zero.  The
	 * setsid() call above may have set our pgrp, so clear
	 * it out before opening the tty...
	 */
#if defined HAVE_SETPGID
	setpgid(0, 0);
#else
	setpgrp(0, 0); /* if setpgid isn't available, setpgrp
				 probably takes arguments */
#endif
	close(open(line, O_RDWR));
# endif
	if (t != 0)
		dup2(t, 0);
	if (t != 1)
		dup2(t, 1);
	if (t != 2)
		dup2(t, 2);
	if (t > 2)
		close(t);
	return(0);
}
#endif	/* BSD <= 43 */

/*
 * startslave(host)
 *
 * Given a hostname, do whatever
 * is necessary to startup the login process on the slave side of the pty.
 */

/* ARGSUSED */
	void
startslave(char *host, int autologin, char *autoname)
{
	int i;
	char name[256];

#if	defined(AUTHENTICATION)
	if (!autoname || !autoname[0])
		autologin = 0;

	if (autologin < auth_level) {
		fatal(net, "Authorization failed");
		exit(1);
	}
#endif

      {
	char *tbuf =
	  "\r\n*** Connection not encrypted! "
	  "Communication may be eavesdropped. ***\r\n";
#ifdef ENCRYPTION
	if (!no_warn && (encrypt_output == 0 || decrypt_input == 0))
#endif
	  writenet((unsigned char*)tbuf, strlen(tbuf));
      }
# ifdef	PARENT_DOES_UTMP
	utmp_sig_init();
# endif	/* PARENT_DOES_UTMP */

	if ((i = fork()) < 0)
		fatalperror(net, "fork");
	if (i) {
# ifdef PARENT_DOES_UTMP
		/*
		 * Cray parent will create utmp entry for child and send
		 * signal to child to tell when done.  Child waits for signal
		 * before doing anything important.
		 */
		int pid = i;
		void sigjob P((int));

		setpgrp();
		utmp_sig_reset();		/* reset handler to default */
		/*
		 * Create utmp entry for child
		 */
		time(&wtmp.ut_time);
		wtmp.ut_type = LOGIN_PROCESS;
		wtmp.ut_pid = pid;
		SCPYN(wtmp.ut_user, "LOGIN");
		SCPYN(wtmp.ut_host, host);
		SCPYN(wtmp.ut_line, line + sizeof("/dev/") - 1);
#ifndef	__hpux
		SCPYN(wtmp.ut_id, wtmp.ut_line+3);
#else
		SCPYN(wtmp.ut_id, wtmp.ut_line+7);
#endif
		pututline(&wtmp);
		endutent();
		if ((i = open(wtmpf, O_WRONLY|O_APPEND)) >= 0) {
			write(i, &wtmp, sizeof(struct utmp));
			close(i);
		}
#ifdef	CRAY
		signal(WJSIGNAL, sigjob);
#endif
		utmp_sig_notify(pid);
# endif	/* PARENT_DOES_UTMP */
	} else {
	  getptyslave();
	  start_login(host, autologin, autoname);
	  /*NOTREACHED*/
	}
}

char	*envinit[3];
extern char **environ;

	void
init_env(void)
{
	extern char *getenv(const char *);
	char **envp;

	envp = envinit;
	if (*envp = getenv("TZ"))
		*envp++ -= 3;
#if	defined(CRAY) || defined(__hpux)
	else
		*envp++ = "TZ=GMT0";
#endif
	*envp = 0;
	environ = envinit;
}

/*
 * scrub_env()
 *
 * Remove variables from the environment that might cause login to
 * behave in a bad manner. To avoid this, login should be staticly
 * linked.
 */

static void scrub_env(void)
{
  static char *remove[] = { "LD_", "_RLD_", "LIBPATH=", "IFS=", NULL };

  char **cpp, **cpp2;
  char **p;
  
  for (cpp2 = cpp = environ; *cpp; cpp++) {
      for(p = remove; *p; p++)
	  if(strncmp(*cpp, *p, strlen(*p)) == 0)
	      break;
      if(*p == NULL)
	  *cpp2++ = *cpp;
  }
  *cpp2 = 0;
}


struct arg_val {
  int size;
  int argc;
  char **argv;
};

int addarg(struct arg_val*, char*);

/*
 * start_login(host)
 *
 * Assuming that we are now running as a child processes, this
 * function will turn us into the login process.
 */

void start_login(char *host, int autologin, char *name)
{
	char *cp;
	struct arg_val argv;
	extern char *getenv(const char *);

#ifdef	HAVE_UTMPX
	char id_buf[3];
	int ptynum;
	int pid = getpid();
	struct utmpx utmpx;
#endif

#ifdef	HAVE_UTMPX
	/*
	 * Create utmp entry for child
	 */

	memset(&utmpx, 0, sizeof(utmpx));
	SCPYN(utmpx.ut_user, ".telnet");

	SCPYN(utmpx.ut_line, line_nodev);
	utmpx.ut_pid = pid;
	SCPYN(utmpx.ut_id, utid);
	
	utmpx.ut_type = LOGIN_PROCESS;
	gettimeofday(&utmpx.ut_tv, NULL);
	if (pututxline(&utmpx) == NULL)
		fatal(net, "pututxline failed");
#endif

	scrub_env();
	
	/*
	 * -h : pass on name of host.
	 *		WARNING:  -h is accepted by login if and only if
	 *			getuid() == 0.
	 * -p : don't clobber the environment (so terminal type stays set).
	 *
	 * -f : force this login, he has already been authenticated
	 */

	/* init argv structure */ 
	argv.size=0;
	argv.argc=0;
	argv.argv=(char**)malloc(0); /*so we can call realloc later */

	addarg(&argv, "login");

#if	!defined(NO_LOGIN_H)

# if	defined (AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	/*
	 * Don't add the "-h host" option if we are going
	 * to be adding the "-r host" option down below...
	 */
	if ((auth_level < 0) || (autologin != AUTH_VALID))
# endif
	{
		addarg(&argv, "-h");
		addarg(&argv, host);
	}
#endif
#if	!defined(NO_LOGIN_P)
	addarg(&argv, "-p");
#endif
#ifdef	LINEMODE
	/*
	 * Set the environment variable "LINEMODE" to either
	 * "real" or "kludge" if we are operating in either
	 * real or kludge linemode.
	 */
	if (lmodetype == REAL_LINEMODE)
		setenv("LINEMODE", "real", 1);
# ifdef KLUDGELINEMODE
	else if (lmodetype == KLUDGE_LINEMODE || lmodetype == KLUDGE_OK)
		setenv("LINEMODE", "kludge", 1);
# endif
#endif
#if	defined (AUTHENTICATION)
	if (auth_level < 0 || autologin != AUTH_VALID) {
		if(!no_warn)
		  printf("User not authenticated. "
			 "Using plaintext username and password\r\n");
		if (require_otp) {
		  addarg(&argv, "-a");
		  addarg(&argv, "otp");
		}
		if(log_unauth) {
		  char *u;
		  if(name[0]) u = name;
		  else u=getenv("USER");
		  u = u ? u : "unknown user";
		  syslog(LOG_INFO, "unauthenticated access from %s (%s)", 
			 host, u);
		}
	}
	if (auth_level >= 0 && autologin == AUTH_VALID) {
# if	!defined(NO_LOGIN_F)
		addarg(&argv, "-f");
		addarg(&argv, "--");
		addarg(&argv, name);
# else
#  if defined(LOGIN_R)
		/*
		 * We don't have support for "login -f", but we
		 * can fool /bin/login into thinking that we are
		 * rlogind, and allow us to log in without a
		 * password.  The rlogin protocol expects
		 *	local-user\0remote-user\0term/speed\0
		 */

		if (ourpty > 2) {
			char *cp;
			char speed[128];
			int isecho, israw, xpty, len;
			extern int def_rspeed;
#  ifndef LOGIN_HOST
			/*
			 * Tell login that we are coming from "localhost".
			 * If we passed in the real host name, then the
			 * user would have to allow .rhost access from
			 * every machine that they want authenticated
			 * access to work from, which sort of defeats
			 * the purpose of an authenticated login...
			 * So, we tell login that the session is coming
			 * from "localhost", and the user will only have
			 * to have "localhost" in their .rhost file.
			 */
#			define LOGIN_HOST "localhost"
#  endif /* LOGIN_HOST */
			addarg(&argv, "-r");
			addarg(&argv, LOGIN_HOST);

			xpty = ourpty;
#ifdef STREAMSPTY
			if (really_stream)
				ttyfd = 0;
			else
#endif
				pty = 0;

			init_termbuf();
			isecho = tty_isecho();
			israw = tty_israw();
			if (isecho || !israw) {
				tty_setecho(0);		/* Turn off echo */
				tty_setraw(1);		/* Turn on raw */
				set_termbuf();
			}
			len = strlen(name)+1;
			write(xpty, name, len);
			write(xpty, name, len);
			sprintf(speed, "%s/%d", (cp = getenv("TERM")) ? cp : "",
				(def_rspeed > 0) ? def_rspeed : 9600);
			len = strlen(speed)+1;
			write(xpty, speed, len);

			if (isecho || !israw) {
				init_termbuf();
				tty_setecho(isecho);
				tty_setraw(israw);
				set_termbuf();
				if (!israw) {
					/*
					 * Write a newline to ensure
					 * that login will be able to
					 * read the line...
					 */
					write(xpty, "\n", 1);
				}
			}
			ourpty = xpty;
		}
#  else /* LOGIN_R */
		addarg(&argv, "--");
		addarg(&argv, name);
#  endif
# endif /* NO_LOGIN_F */
	} /* else */ /* esc@magic.fi; removed stupid else */
#endif
	if (getenv("USER")) {
	        addarg(&argv, "--");
		addarg(&argv, getenv("USER"));
#if	defined(LOGIN_ARGS) && defined(NO_LOGIN_P)
		{
			char **cpp;
			for (cpp = environ; *cpp; cpp++) {
				addarg(&argv, *cpp);
			}
		}
#endif
		/*
		 * Assume that login will set the USER variable
		 * correctly.  For SysV systems, this means that
		 * USER will no longer be set, just LOGNAME by
		 * login.  (The problem is that if the auto-login
		 * fails, and the user then specifies a different
		 * account name, he can get logged in with both
		 * LOGNAME and USER in his environment, but the
		 * USER value will be wrong.
		 */
		unsetenv("USER");
	}
#if	defined(AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	if (ourpty > 2)
		close(ourpty);
#endif
	closelog();
	/*
	 * This sleep(1) is in here so that telnetd can
	 * finish up with the tty.  There's a race condition
	 * the login banner message gets lost...
	 */
	sleep(1);
#ifdef SHOW_LOGIN_ARGS
	{ 
	  int i;
	  for(i=0;argv.argv[i];i++)
	    fprintf(stderr, "%s ", argv.argv[i]);
	  fprintf(stderr, "\n");
	}
#endif

	execv(new_login, argv.argv);

	syslog(LOG_ERR, "%s: %m\n", new_login);
	fatalperror(net, new_login);
	/*NOTREACHED*/
}



int addarg(struct arg_val *argv, char *val)
{
  if(argv->size <= argv->argc+1){
    argv->argv = (char**)realloc(argv->argv, sizeof(char*) * (argv->size + 10));
    if(argv->argv == NULL)
      return 1; /* this should probably be handled better */
    argv->size+=10;
  }
  argv->argv[argv->argc++]=val;
  argv->argv[argv->argc]=NULL;
  return 0;
}


/*
 * rmut()
 *
 * This is the function called by cleanup() to
 * remove the utmp entry for this person.
 */

#ifdef	HAVE_UTMPX
static
void
rmut(void)
{
	int f;
	int found = 0;
	struct utmp *u, *utmp;
	int nutmp;
	struct stat statbf;

	struct utmpx *utxp, utmpx;

	/*
	 * This updates the utmpx and utmp entries and make a wtmp/x entry
	 */

	setutxent();
	memset(&utmpx, 0, sizeof(utmpx));
	strncpy(utmpx.ut_id, utid, sizeof(utmpx.ut_id));
	utmpx.ut_type = LOGIN_PROCESS;
	utxp = getutxid(&utmpx);
	if (utxp) {
	    strcpy(utxp->ut_user, "");
	    utxp->ut_type = DEAD_PROCESS;
#ifdef _STRUCT___EXIT_STATUS
	    utxp->ut_exit.__e_termination = 0;
	    utxp->ut_exit.__e_exit = 0;
#else
	    utxp->ut_exit.e_termination = 0;
	    utxp->ut_exit.e_exit = 0;
#endif
	    gettimeofday(&utxp->ut_tv, NULL);
	    pututxline(utxp);
#ifdef WTMPX_FILE
	    updwtmpx(WTMPX_FILE, utxp);
#endif
	}
	endutxent();
}  /* end of rmut */
#endif

#if !defined(HAVE_UTMPX) && !(defined(CRAY) || defined(__hpux)) && BSD <= 43
static
void
rmut(void)
{
	int f;
	int found = 0;
	struct utmp *u, *utmp;
	int nutmp;
	struct stat statbf;

	f = open(utmpf, O_RDWR);
	if (f >= 0) {
		fstat(f, &statbf);
		utmp = (struct utmp *)malloc((unsigned)statbf.st_size);
		if (!utmp)
			syslog(LOG_ERR, "utmp malloc failed");
		if (statbf.st_size && utmp) {
			nutmp = read(f, utmp, (int)statbf.st_size);
			nutmp /= sizeof(struct utmp);

			for (u = utmp ; u < &utmp[nutmp] ; u++) {
				if (SCMPN(u->ut_line, line+5) ||
				    u->ut_name[0]==0)
					continue;
				lseek(f, ((long)u)-((long)utmp), L_SET);
				SCPYN(u->ut_name, "");
#ifdef HAVE_UT_HOST
				SCPYN(u->ut_host, "");
#endif
				time(&u->ut_time);
				write(f, u, sizeof(wtmp));
				found++;
			}
		}
		close(f);
	}
	if (found) {
		f = open(wtmpf, O_WRONLY|O_APPEND);
		if (f >= 0) {
			SCPYN(wtmp.ut_line, line+5);
			SCPYN(wtmp.ut_name, "");
#ifdef HAVE_UT_HOST
			SCPYN(wtmp.ut_host, "");
#endif
			time(&wtmp.ut_time);
			write(f, &wtmp, sizeof(wtmp));
			close(f);
		}
	}
	chmod(line, 0666);
	chown(line, 0, 0);
	line[strlen("/dev/")] = 'p';
	chmod(line, 0666);
	chown(line, 0, 0);
}  /* end of rmut */
#endif	/* CRAY */

#if defined(__hpux) && !defined(HAVE_UTMPX)
static
void
rmut (char *line)
{
	struct utmp utmp;
	struct utmp *utptr;
	int fd;			/* for /etc/wtmp */

	utmp.ut_type = USER_PROCESS;
	strncpy(utmp.ut_id, line+12, sizeof(utmp.ut_id));
	setutent();
	utptr = getutid(&utmp);
	/* write it out only if it exists */
	if (utptr) {
		utptr->ut_type = DEAD_PROCESS;
		utptr->ut_time = time((long *) 0);
		pututline(utptr);
		/* set wtmp entry if wtmp file exists */
		if ((fd = open(wtmpf, O_WRONLY | O_APPEND)) >= 0) {
			write(fd, utptr, sizeof(utmp));
			close(fd);
		}
	}
	endutent();

	chmod(line, 0666);
	chown(line, 0, 0);
	line[14] = line[13];
	line[13] = line[12];
	line[8] = 'm';
	line[9] = '/';
	line[10] = 'p';
	line[11] = 't';
	line[12] = 'y';
	chmod(line, 0666);
	chown(line, 0, 0);
}
#endif

/*
 * cleanup()
 *
 * This is the routine to call when we are all through, to
 * clean up anything that needs to be cleaned up.
 */

#ifdef PARENT_DOES_UTMP

void
cleanup(int sig)
{
#  ifdef CRAY
    static int incleanup = 0;
    int t;
    int child_status; /* status of child process as returned by waitpid */
    int flags = WNOHANG|WUNTRACED;
    
    /*
     * 1: Pick up the zombie, if we are being called
     *    as the signal handler.
     * 2: If we are a nested cleanup(), return.
     * 3: Try to clean up TMPDIR.
     * 4: Fill in utmp with shutdown of process.
     * 5: Close down the network and pty connections.
     * 6: Finish up the TMPDIR cleanup, if needed.
     */
    if (sig == SIGCHLD) {
	while (waitpid(-1, &child_status, flags) > 0)
	    ;	/* VOID */
	/* Check if the child process was stopped
	 * rather than exited.  We want cleanup only if
	 * the child has died.
	 */
	if (WIFSTOPPED(child_status)) {
	    return;
	}
    }
    t = sigblock(sigmask(SIGCHLD));
    if (incleanup) {
		sigsetmask(t);
		return;
    }
    incleanup = 1;
    sigsetmask(t);
    
    t = cleantmp(&wtmp);
    setutent();	/* just to make sure */
#  endif /* CRAY */
    rmut(line);
    close(ourpty);
    shutdown(net, 2);
#  ifdef CRAY
    if (t == 0)
	cleantmp(&wtmp);
#  endif /* CRAY */
    exit(1);
}

#else /* PARENT_DOES_UTMP */

void
cleanup(int sig)
{
#if defined(HAVE_UTMPX) || !defined(HAVE_LOGWTMP)
    rmut();
#ifdef HAVE_VHANGUP
    vhangup(); /* XXX */
#endif
#else
    char *p;
    
    p = line + sizeof("/dev/") - 1;
    if (logout(p))
	logwtmp(p, "", "");
    chmod(line, 0666);
    chown(line, 0, 0);
    *p = 'p';
    chmod(line, 0666);
    chown(line, 0, 0);
#endif
    shutdown(net, 2);
    exit(1);
}

#endif /* PARENT_DOES_UTMP */

#if defined(PARENT_DOES_UTMP)
/*
 * _utmp_sig_rcv
 * utmp_sig_init
 * utmp_sig_wait
 *	These three functions are used to coordinate the handling of
 *	the utmp file between the server and the soon-to-be-login shell.
 *	The server actually creates the utmp structure, the child calls
 *	utmp_sig_wait(), until the server calls utmp_sig_notify() and
 *	signals the future-login shell to proceed.
 */
static int caught=0;		/* NZ when signal intercepted */
static void (*func)();		/* address of previous handler */

	void
_utmp_sig_rcv(sig)
	int sig;
{
	caught = 1;
	signal(SIGUSR1, func);
}

	void
utmp_sig_init()
{
	/*
	 * register signal handler for UTMP creation
	 */
	if ((int)(func = signal(SIGUSR1, _utmp_sig_rcv)) == -1)
		fatalperror(net, "telnetd/signal");
}

	void
utmp_sig_reset()
{
	signal(SIGUSR1, func);	/* reset handler to default */
}

# ifdef __hpux
# define sigoff() /* do nothing */
# define sigon() /* do nothing */
# endif

	void
utmp_sig_wait()
{
	/*
	 * Wait for parent to write our utmp entry.
	 */
	sigoff();
	while (caught == 0) {
		pause();	/* wait until we get a signal (sigon) */
		sigoff();	/* turn off signals while we check caught */
	}
	sigon();		/* turn on signals again */
}

	void
utmp_sig_notify(pid)
{
	kill(pid, SIGUSR1);
}

# ifdef CRAY
static int gotsigjob = 0;

	/*ARGSUSED*/
	void
sigjob(sig)
	int sig;
{
	int jid;
	struct jobtemp *jp;

	while ((jid = waitjob(NULL)) != -1) {
		if (jid == 0) {
			return;
		}
		gotsigjob++;
		jobend(jid, NULL, NULL);
	}
}

/*
 *	jid_getutid:
 *		called by jobend() before calling cleantmp()
 *		to find the correct $TMPDIR to cleanup.
 */

	struct utmp *
jid_getutid(jid)
	int jid;
{
	struct utmp *cur = NULL;

	setutent();	/* just to make sure */
	while (cur = getutent()) {
		if ( (cur->ut_type != NULL) && (jid == cur->ut_jid) ) {
			return(cur);
		}
	}

	return(0);
}

/*
 * Clean up the TMPDIR that login created.
 * The first time this is called we pick up the info
 * from the utmp.  If the job has already gone away,
 * then we'll clean up and be done.  If not, then
 * when this is called the second time it will wait
 * for the signal that the job is done.
 */
	int
cleantmp(wtp)
	struct utmp *wtp;
{
	struct utmp *utp;
	static int first = 1;
	int mask, omask, ret;
	extern struct utmp *getutid P((const struct utmp *_Id));


	mask = sigmask(WJSIGNAL);

	if (first == 0) {
		omask = sigblock(mask);
		while (gotsigjob == 0)
			sigpause(omask);
		return(1);
	}
	first = 0;
	setutent();	/* just to make sure */

	utp = getutid(wtp);
	if (utp == 0) {
		syslog(LOG_ERR, "Can't get /etc/utmp entry to clean TMPDIR");
		return(-1);
	}
	/*
	 * Nothing to clean up if the user shell was never started.
	 */
	if (utp->ut_type != USER_PROCESS || utp->ut_jid == 0)
		return(1);

	/*
	 * Block the WJSIGNAL while we are in jobend().
	 */
	omask = sigblock(mask);
	ret = jobend(utp->ut_jid, utp->ut_tpath, utp->ut_user);
	sigsetmask(omask);
	return(ret);
}

	int
jobend(jid, path, user)
	int jid;
	char *path;
	char *user;
{
	static int saved_jid = 0;
	static int pty_saved_jid = 0;
	static char saved_path[sizeof(wtmp.ut_tpath)+1];
	static char saved_user[sizeof(wtmp.ut_user)+1];

	/*
	 * this little piece of code comes into play
	 * only when ptyreconnect is used to reconnect
	 * to an previous session.
	 *
	 * this is the only time when the
	 * "saved_jid != jid" code is executed.
	 */

	if ( saved_jid && saved_jid != jid ) {
		if (!path) {	/* called from signal handler */
			pty_saved_jid = jid;
		} else {
			pty_saved_jid = saved_jid;
		}
	}

	if (path) {
		strncpy(saved_path, path, sizeof(wtmp.ut_tpath));
		strncpy(saved_user, user, sizeof(wtmp.ut_user));
		saved_path[sizeof(saved_path)] = '\0';
		saved_user[sizeof(saved_user)] = '\0';
	}
	if (saved_jid == 0) {
		saved_jid = jid;
		return(0);
	}

	/* if the jid has changed, get the correct entry from the utmp file */

	if ( saved_jid != jid ) {
		struct utmp *utp = NULL;
		struct utmp *jid_getutid();

		utp = jid_getutid(pty_saved_jid);

		if (utp == 0) {
			syslog(LOG_ERR, "Can't get /etc/utmp entry to clean TMPDIR");
			return(-1);
		}

		cleantmpdir(jid, utp->ut_tpath, utp->ut_user);
		return(1);
	}

	cleantmpdir(jid, saved_path, saved_user);
	return(1);
}

/*
 * Fork a child process to clean up the TMPDIR
 */
cleantmpdir(jid, tpath, user)
	int jid;
	char *tpath;
	char *user;
{
	switch(fork()) {
	case -1:
		syslog(LOG_ERR, "TMPDIR cleanup(%s): fork() failed: %m\n",
							tpath);
		break;
	case 0:
		execl(CLEANTMPCMD, CLEANTMPCMD, user, tpath, 0);
		syslog(LOG_ERR, "TMPDIR cleanup(%s): execl(%s) failed: %m\n",
							tpath, CLEANTMPCMD);
		exit(1);
	default:
		/*
		 * Forget about child.  We will exit, and
		 * /etc/init will pick it up.
		 */
		break;
	}
}
# endif /* CRAY */
#endif	/* defined(PARENT_DOES_UTMP) && !defined(NEWINIT) */
