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

#define PRINTOPTIONS
#include "telnetd.h"

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif

/*
 * utility functions performing io related tasks
 */

/*
 * ttloop
 *
 *	A small subroutine to flush the network output buffer, get some data
 * from the network, and pass it through the telnet state machine.  We
 * also flush the pty input buffer (by dropping its data) if it becomes
 * too full.
 */

    void
ttloop(void)
{
    void netflush(void);

    DIAG(TD_REPORT, {snprintf(nfrontp, BUFSIZ - (nfrontp - netobuf),
			      "td: ttloop\r\n");
		     nfrontp += strlen(nfrontp);});
    if (nfrontp-nbackp) {
	netflush();
    }
    ncc = read(net, netibuf, sizeof netibuf);
    if (ncc < 0) {
	syslog(LOG_INFO, "ttloop:  read: %m\n");
	exit(1);
    } else if (ncc == 0) {
	syslog(LOG_INFO, "ttloop:  peer died: %m\n");
	exit(1);
    }
    DIAG(TD_REPORT, {snprintf(nfrontp, BUFSIZ - (nfrontp - netobuf),
			      "td: ttloop read %d chars\r\n", ncc);
		     nfrontp += strlen(nfrontp);});
    netip = netibuf;
    telrcv();			/* state machine */
    if (ncc > 0) {
	pfrontp = pbackp = ptyobuf;
	telrcv();
    }
}  /* end of ttloop */

/*
 * Check a descriptor to see if out of band data exists on it.
 */
    int
stilloob(int s)
       	  		/* socket number */
{
    static struct timeval timeout = { 0 };
    fd_set	excepts;
    int value;

    do {
	FD_ZERO(&excepts);
	FD_SET(s, &excepts);
	value = select(s+1, 0, 0, &excepts, &timeout);
    } while ((value == -1) && (errno == EINTR));

    if (value < 0) {
	fatalperror(ourpty, "select");
    }
    if (FD_ISSET(s, &excepts)) {
	return 1;
    } else {
	return 0;
    }
}

	void
ptyflush(void)
{
	int n;

	if ((n = pfrontp - pbackp) > 0) {
		DIAG((TD_REPORT | TD_PTYDATA),
			{ snprintf(nfrontp,
				   BUFSIZ - (nfrontp - netobuf),
				   "td: ptyflush %d chars\r\n", n);
			  nfrontp += strlen(nfrontp); });
		DIAG(TD_PTYDATA, printdata("pd", pbackp, n));
		n = write(ourpty, pbackp, n);
	}
	if (n < 0) {
		if (errno == EWOULDBLOCK || errno == EINTR)
			return;
		cleanup(0);
	}
	pbackp += n;
	if (pbackp == pfrontp)
		pbackp = pfrontp = ptyobuf;
}

/*
 * nextitem()
 *
 *	Return the address of the next "item" in the TELNET data
 * stream.  This will be the address of the next character if
 * the current address is a user data character, or it will
 * be the address of the character following the TELNET command
 * if the current address is a TELNET IAC ("I Am a Command")
 * character.
 */
    char *
nextitem(char *current)
{
    if ((*current&0xff) != IAC) {
	return current+1;
    }
    switch (*(current+1)&0xff) {
    case DO:
    case DONT:
    case WILL:
    case WONT:
	return current+3;
    case SB:		/* loop forever looking for the SE */
	{
	    char *look = current+2;

	    for (;;) {
		if ((*look++&0xff) == IAC) {
		    if ((*look++&0xff) == SE) {
			return look;
		    }
		}
	    }
	}
    default:
	return current+2;
    }
}  /* end of nextitem */


/*
 * netclear()
 *
 *	We are about to do a TELNET SYNCH operation.  Clear
 * the path to the network.
 *
 *	Things are a bit tricky since we may have sent the first
 * byte or so of a previous TELNET command into the network.
 * So, we have to scan the network buffer from the beginning
 * until we are up to where we want to be.
 *
 *	A side effect of what we do, just to keep things
 * simple, is to clear the urgent data pointer.  The principal
 * caller should be setting the urgent data pointer AFTER calling
 * us in any case.
 */
    void
netclear(void)
{
    char *thisitem, *next;
    char *good;
#define	wewant(p)	((nfrontp > p) && ((*p&0xff) == IAC) && \
				((*(p+1)&0xff) != EC) && ((*(p+1)&0xff) != EL))

#if	defined(ENCRYPTION)
    thisitem = nclearto > netobuf ? nclearto : netobuf;
#else
    thisitem = netobuf;
#endif

    while ((next = nextitem(thisitem)) <= nbackp) {
	thisitem = next;
    }

    /* Now, thisitem is first before/at boundary. */

#if	defined(ENCRYPTION)
    good = nclearto > netobuf ? nclearto : netobuf;
#else
    good = netobuf;	/* where the good bytes go */
#endif

    while (nfrontp > thisitem) {
	if (wewant(thisitem)) {
	    int length;

	    next = thisitem;
	    do {
		next = nextitem(next);
	    } while (wewant(next) && (nfrontp > next));
	    length = next-thisitem;
	    memmove(good, thisitem, length);
	    good += length;
	    thisitem = next;
	} else {
	    thisitem = nextitem(thisitem);
	}
    }

    nbackp = netobuf;
    nfrontp = good;		/* next byte to be sent */
    neturg = 0;
}  /* end of netclear */

/*
 *  netflush
 *		Send as much data as possible to the network,
 *	handling requests for urgent data.
 */
    void
netflush(void)
{
    int n;
    extern int not42;

    if ((n = nfrontp - nbackp) > 0) {
	DIAG(TD_REPORT,
	    { snprintf(nfrontp, BUFSIZ - (nfrontp - netobuf),
		       "td: netflush %d chars\r\n", n);
	      n += strlen(nfrontp);  /* get count first */
	      nfrontp += strlen(nfrontp);  /* then move pointer */
	    });
#if	defined(ENCRYPTION)
	if (encrypt_output) {
		char *s = nclearto ? nclearto : nbackp;
		if (nfrontp - s > 0) {
			(*encrypt_output)((unsigned char *)s, nfrontp-s);
			nclearto = nfrontp;
		}
	}
#endif
	/*
	 * if no urgent data, or if the other side appears to be an
	 * old 4.2 client (and thus unable to survive TCP urgent data),
	 * write the entire buffer in non-OOB mode.
	 */
	if ((neturg == 0) || (not42 == 0)) {
	    n = write(net, nbackp, n);	/* normal write */
	} else {
	    n = neturg - nbackp;
	    /*
	     * In 4.2 (and 4.3) systems, there is some question about
	     * what byte in a sendOOB operation is the "OOB" data.
	     * To make ourselves compatible, we only send ONE byte
	     * out of band, the one WE THINK should be OOB (though
	     * we really have more the TCP philosophy of urgent data
	     * rather than the Unix philosophy of OOB data).
	     */
	    if (n > 1) {
		n = send(net, nbackp, n-1, 0);	/* send URGENT all by itself */
	    } else {
		n = send(net, nbackp, n, MSG_OOB);	/* URGENT data */
	    }
	}
    }
    if (n < 0) {
	if (errno == EWOULDBLOCK || errno == EINTR)
		return;
	cleanup(0);
    }
    nbackp += n;
#if	defined(ENCRYPTION)
    if (nbackp > nclearto)
	nclearto = 0;
#endif
    if (nbackp >= neturg) {
	neturg = 0;
    }
    if (nbackp == nfrontp) {
	nbackp = nfrontp = netobuf;
#if	defined(ENCRYPTION)
	nclearto = 0;
#endif
    }
    return;
}  /* end of netflush */


/*
 * writenet
 *
 * Just a handy little function to write a bit of raw data to the net.
 * It will force a transmit of the buffer if necessary
 *
 * arguments
 *    ptr - A pointer to a character string to write
 *    len - How many bytes to write
 */
	void
writenet(unsigned char *ptr, int len)
{
	/* flush buffer if no room for new data) */
	if ((&netobuf[BUFSIZ] - nfrontp) < len) {
		/* if this fails, don't worry, buffer is a little big */
		netflush();
	}

	memmove(nfrontp, ptr, len);
	nfrontp += len;

}  /* end of writenet */


/*
 * miscellaneous functions doing a variety of little jobs follow ...
 */


void fatal(int f, char *msg)
{
	char buf[BUFSIZ];

	snprintf(buf, sizeof(buf), "telnetd: %s.\r\n", msg);
#if	defined(ENCRYPTION)
	if (encrypt_output) {
		/*
		 * Better turn off encryption first....
		 * Hope it flushes...
		 */
		encrypt_send_end();
		netflush();
	}
#endif
	write(f, buf, (int)strlen(buf));
	sleep(1);	/*XXX*/
	exit(1);
}

	void
fatalperror(int f, char *msg)
{
	char buf[BUFSIZ];

	snprintf(buf, sizeof(buf), "%s: %s", msg, strerror(errno));
	fatal(f, buf);
}

char editedhost[32];

void edithost(char *pat, char *host)
{
	char *res = editedhost;

	if (!pat)
		pat = "";
	while (*pat) {
		switch (*pat) {

		case '#':
			if (*host)
				host++;
			break;

		case '@':
			if (*host)
				*res++ = *host++;
			break;

		default:
			*res++ = *pat;
			break;
		}
		if (res == &editedhost[sizeof editedhost - 1]) {
			*res = '\0';
			return;
		}
		pat++;
	}
	if (*host)
		strncpy(res, host,
				sizeof editedhost - (res - editedhost) -1);
	else
		*res = '\0';
	editedhost[sizeof editedhost - 1] = '\0';
}

static char *putlocation;

	void
putstr(char *s)
{

	while (*s)
		putchr(*s++);
}

	void
putchr(int cc)
{
	*putlocation++ = cc;
}

/*
 * This is split on two lines so that SCCS will not see the M
 * between two % signs and expand it...
 */
static char fmtstr[] = { "%l:%M\
%P on %A, %d %B %Y" };

void putf(char *cp, char *where)
{
#ifdef HAVE_UNAME
        struct utsname name;
#endif
	char *slash;
	time_t t;
	char db[100];

/* if we don't have uname, set these to sensible values */
	char *sysname = "Unix", 
	  *machine = "", 
	  *release = "",
	  *version = ""; 

#ifdef HAVE_UNAME
	uname(&name);
	sysname=name.sysname;
	machine=name.machine;
	release=name.release;
	version=name.version;
#endif

	putlocation = where;

	while (*cp) {
		if (*cp != '%') {
			putchr(*cp++);
			continue;
		}
		switch (*++cp) {

		case 't':
#ifdef	STREAMSPTY
			/* names are like /dev/pts/2 -- we want pts/2 */
			slash = strchr(line+1, '/');
#else
			slash = strrchr(line, '/');
#endif
			if (slash == (char *) 0)
				putstr(line);
			else
				putstr(&slash[1]);
			break;

		case 'h':
			putstr(editedhost);
			break;

		case 's':
		  putstr(sysname);
		  break;

		case 'm':
		  putstr(machine);
		  break;

		case 'r':
		  putstr(release);
		  break;

		case 'v':
		  putstr(version);
		  break;

		case 'd':
			time(&t);
			strftime(db, sizeof(db), fmtstr, localtime(&t));
			putstr(db);
			break;

		case '%':
			putchr('%');
			break;
		}
		cp++;
	}
}

#ifdef DIAGNOSTICS
/*
 * Print telnet options and commands in plain text, if possible.
 */
	void
printoption(char *fmt, int option)
{
	if (TELOPT_OK(option))
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s %s\r\n",
			 fmt,
			 TELOPT(option));
	else if (TELCMD_OK(option))
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s %s\r\n",
			 fmt,
			 TELCMD(option));
	else
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s %d\r\n",
			 fmt,
			 option);
	nfrontp += strlen(nfrontp);
	return;
}

    void
printsub(int direction, unsigned char *pointer, int length)
        		          	/* '<' or '>' */
                 	         	/* where suboption data sits */
       			       		/* length of suboption data */
{
    int i;
    char buf[512];

	if (!(diagnostic & TD_OPTIONS))
		return;

	if (direction) {
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "td: %s suboption ",
		     direction == '<' ? "recv" : "send");
	    nfrontp += strlen(nfrontp);
	    if (length >= 3) {
		int j;

		i = pointer[length-2];
		j = pointer[length-1];

		if (i != IAC || j != SE) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "(terminated by ");
		    nfrontp += strlen(nfrontp);
		    if (TELOPT_OK(i))
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%s ",
				 TELOPT(i));
		    else if (TELCMD_OK(i))
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%s ",
				 TELCMD(i));
		    else
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%d ",
				 i);
		    nfrontp += strlen(nfrontp);
		    if (TELOPT_OK(j))
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%s",
				 TELOPT(j));
		    else if (TELCMD_OK(j))
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%s",
				 TELCMD(j));
		    else
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%d",
				 j);
		    nfrontp += strlen(nfrontp);
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     ", not IAC SE!) ");
		    nfrontp += strlen(nfrontp);
		}
	    }
	    length -= 2;
	}
	if (length < 1) {
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "(Empty suboption??\?)");
	    nfrontp += strlen(nfrontp);
	    return;
	}
	switch (pointer[0]) {
	case TELOPT_TTYPE:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "TERMINAL-TYPE ");
	    nfrontp += strlen(nfrontp);
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "IS \"%.*s\"",
			 length-2,
			 (char *)pointer+2);
		break;
	    case TELQUAL_SEND:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "SEND");
		break;
	    default:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "- unknown qualifier %d (0x%x).",
			 pointer[1], pointer[1]);
	    }
	    nfrontp += strlen(nfrontp);
	    break;
	case TELOPT_TSPEED:
	    snprintf(nfrontp,
		    BUFSIZ - (nfrontp - netobuf),
		    "TERMINAL-SPEED");
	    nfrontp += strlen(nfrontp);
	    if (length < 2) {
		snprintf(nfrontp,
			BUFSIZ - (nfrontp - netobuf),
			" (empty suboption??\?)");
		nfrontp += strlen(nfrontp);
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " IS %.*s",
			 length-2,
			 (char *)pointer+2);
		nfrontp += strlen(nfrontp);
		break;
	    default:
		if (pointer[1] == 1)
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " SEND");
		else
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " %d (unknown)",
			     pointer[1]);
		nfrontp += strlen(nfrontp);
		for (i = 2; i < length; i++) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " ?%d?",
			     pointer[i]);
		    nfrontp += strlen(nfrontp);
		}
		break;
	    }
	    break;

	case TELOPT_LFLOW:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "TOGGLE-FLOW-CONTROL");
	    nfrontp += strlen(nfrontp);
	    if (length < 2) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " (empty suboption??\?)");
		nfrontp += strlen(nfrontp);
		break;
	    }
	    switch (pointer[1]) {
	    case LFLOW_OFF:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " OFF");
		break;
	    case LFLOW_ON:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " ON");
		break;
	    case LFLOW_RESTART_ANY:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " RESTART-ANY");
		break;
	    case LFLOW_RESTART_XON:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " RESTART-XON");
		break;
	    default:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " %d (unknown)",
			 pointer[1]);
	    }
	    nfrontp += strlen(nfrontp);
	    for (i = 2; i < length; i++) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " ?%d?",
			 pointer[i]);
		nfrontp += strlen(nfrontp);
	    }
	    break;

	case TELOPT_NAWS:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "NAWS");
	    nfrontp += strlen(nfrontp);
	    if (length < 2) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " (empty suboption??\?)");
		nfrontp += strlen(nfrontp);
		break;
	    }
	    if (length == 2) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " ?%d?",
			 pointer[1]);
		nfrontp += strlen(nfrontp);
		break;
	    }
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     " %d %d (%d)",
		     pointer[1],
		     pointer[2],
		(int)((((unsigned int)pointer[1])<<8)|((unsigned int)pointer[2])));
	    nfrontp += strlen(nfrontp);
	    if (length == 4) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " ?%d?",
			 pointer[3]);
		nfrontp += strlen(nfrontp);
		break;
	    }
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     " %d %d (%d)",
		     pointer[3], pointer[4],
		(int)((((unsigned int)pointer[3])<<8)|((unsigned int)pointer[4])));
	    nfrontp += strlen(nfrontp);
	    for (i = 5; i < length; i++) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " ?%d?",
			 pointer[i]);
		nfrontp += strlen(nfrontp);
	    }
	    break;

	case TELOPT_LINEMODE:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "LINEMODE ");
	    nfrontp += strlen(nfrontp);
	    if (length < 2) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " (empty suboption??\?)");
		nfrontp += strlen(nfrontp);
		break;
	    }
	    switch (pointer[1]) {
	    case WILL:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "WILL ");
		goto common;
	    case WONT:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "WONT ");
		goto common;
	    case DO:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "DO ");
		goto common;
	    case DONT:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "DONT ");
	    common:
		nfrontp += strlen(nfrontp);
		if (length < 3) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "(no option??\?)");
		    nfrontp += strlen(nfrontp);
		    break;
		}
		switch (pointer[2]) {
		case LM_FORWARDMASK:
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "Forward Mask");
		    nfrontp += strlen(nfrontp);
		    for (i = 3; i < length; i++) {
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " %x", pointer[i]);
			nfrontp += strlen(nfrontp);
		    }
		    break;
		default:
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "%d (unknown)",
			     pointer[2]);
		    nfrontp += strlen(nfrontp);
		    for (i = 3; i < length; i++) {
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " %d",
				 pointer[i]);
			nfrontp += strlen(nfrontp);
		    }
		    break;
		}
		break;

	    case LM_SLC:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "SLC");
		nfrontp += strlen(nfrontp);
		for (i = 2; i < length - 2; i += 3) {
		    if (SLC_NAME_OK(pointer[i+SLC_FUNC]))
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " %s",
				 SLC_NAME(pointer[i+SLC_FUNC]));
		    else
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " %d",
				 pointer[i+SLC_FUNC]);
		    nfrontp += strlen(nfrontp);
		    switch (pointer[i+SLC_FLAGS]&SLC_LEVELBITS) {
		    case SLC_NOSUPPORT:
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " NOSUPPORT"); break;
		    case SLC_CANTCHANGE:
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " CANTCHANGE"); break;
		    case SLC_VARIABLE:
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " VARIABLE");
			break;
		    case SLC_DEFAULT:
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " DEFAULT");
			break;
		    }
		    nfrontp += strlen(nfrontp);
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "%s%s%s",
			     pointer[i+SLC_FLAGS]&SLC_ACK ? "|ACK" : "",
			     pointer[i+SLC_FLAGS]&SLC_FLUSHIN ? "|FLUSHIN" : "",
			     pointer[i+SLC_FLAGS]&SLC_FLUSHOUT ? "|FLUSHOUT" : "");
		    nfrontp += strlen(nfrontp);
		    if (pointer[i+SLC_FLAGS]& ~(SLC_ACK|SLC_FLUSHIN|
						SLC_FLUSHOUT| SLC_LEVELBITS)) {
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "(0x%x)",
				 pointer[i+SLC_FLAGS]);
			nfrontp += strlen(nfrontp);
		    }
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " %d;",
			     pointer[i+SLC_VALUE]);
		    nfrontp += strlen(nfrontp);
		    if ((pointer[i+SLC_VALUE] == IAC) &&
			(pointer[i+SLC_VALUE+1] == IAC))
				i++;
		}
		for (; i < length; i++) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " ?%d?",
			     pointer[i]);
		    nfrontp += strlen(nfrontp);
		}
		break;

	    case LM_MODE:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "MODE ");
		nfrontp += strlen(nfrontp);
		if (length < 3) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "(no mode??\?)");
		    nfrontp += strlen(nfrontp);
		    break;
		}
		{
		    char tbuf[32];
		    snprintf(tbuf,
			     sizeof(tbuf),
			     "%s%s%s%s%s",
			     pointer[2]&MODE_EDIT ? "|EDIT" : "",
			     pointer[2]&MODE_TRAPSIG ? "|TRAPSIG" : "",
			     pointer[2]&MODE_SOFT_TAB ? "|SOFT_TAB" : "",
			     pointer[2]&MODE_LIT_ECHO ? "|LIT_ECHO" : "",
			     pointer[2]&MODE_ACK ? "|ACK" : "");
		    snprintf(nfrontp,
			    BUFSIZ - (nfrontp - netobuf),
			    "%s",
			    tbuf[1] ? &tbuf[1] : "0");
		    nfrontp += strlen(nfrontp);
		}
		if (pointer[2]&~(MODE_EDIT|MODE_TRAPSIG|MODE_ACK)) {
		    snprintf(nfrontp,
			    BUFSIZ - (nfrontp - netobuf),
			     " (0x%x)",
			     pointer[2]);
		    nfrontp += strlen(nfrontp);
		}
		for (i = 3; i < length; i++) {
		    snprintf(nfrontp,
			    BUFSIZ - (nfrontp - netobuf),
			     " ?0x%x?",
			     pointer[i]);
		    nfrontp += strlen(nfrontp);
		}
		break;
	    default:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%d (unknown)",
			 pointer[1]);
		nfrontp += strlen(nfrontp);
		for (i = 2; i < length; i++) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " %d", pointer[i]);
		    nfrontp += strlen(nfrontp);
		}
	    }
	    break;

	case TELOPT_STATUS: {
	    char *cp;
	    int j, k;

	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "STATUS");
	    nfrontp += strlen(nfrontp);

	    switch (pointer[1]) {
	    default:
		if (pointer[1] == TELQUAL_SEND)
		    snprintf(nfrontp,
			    BUFSIZ - (nfrontp - netobuf),
			     " SEND");
		else
		    snprintf(nfrontp,
			    BUFSIZ - (nfrontp - netobuf),
			     " %d (unknown)",
			     pointer[1]);
		nfrontp += strlen(nfrontp);
		for (i = 2; i < length; i++) {
		    snprintf(nfrontp,
			    BUFSIZ - (nfrontp - netobuf),
			     " ?%d?",
			     pointer[i]);
		    nfrontp += strlen(nfrontp);
		}
		break;
	    case TELQUAL_IS:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " IS\r\n");
		nfrontp += strlen(nfrontp);

		for (i = 2; i < length; i++) {
		    switch(pointer[i]) {
		    case DO:	cp = "DO"; goto common2;
		    case DONT:	cp = "DONT"; goto common2;
		    case WILL:	cp = "WILL"; goto common2;
		    case WONT:	cp = "WONT"; goto common2;
		    common2:
			i++;
			if (TELOPT_OK(pointer[i]))
			    snprintf(nfrontp,
				     BUFSIZ - (nfrontp - netobuf),
				     " %s %s",
				     cp,
				     TELOPT(pointer[i]));
			else
			    snprintf(nfrontp,
				     BUFSIZ - (nfrontp - netobuf),
				     " %s %d",
				     cp,
				     pointer[i]);
			nfrontp += strlen(nfrontp);

			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "\r\n");
			nfrontp += strlen(nfrontp);
			break;

		    case SB:
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " SB ");
			nfrontp += strlen(nfrontp);
			i++;
			j = k = i;
			while (j < length) {
			    if (pointer[j] == SE) {
				if (j+1 == length)
				    break;
				if (pointer[j+1] == SE)
				    j++;
				else
				    break;
			    }
			    pointer[k++] = pointer[j++];
			}
			printsub(0, &pointer[i], k - i);
			if (i < length) {
			    snprintf(nfrontp,
				    BUFSIZ - (nfrontp - netobuf),
				    " SE");
			    nfrontp += strlen(nfrontp);
			    i = j;
			} else
			    i = j - 1;

			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "\r\n");
			nfrontp += strlen(nfrontp);

			break;

		    default:
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " %d",
				 pointer[i]);
			nfrontp += strlen(nfrontp);
			break;
		    }
		}
		break;
	    }
	    break;
	  }

	case TELOPT_XDISPLOC:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "X-DISPLAY-LOCATION ");
	    nfrontp += strlen(nfrontp);
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "IS \"%.*s\"",
			 length-2,
			 (char *)pointer+2);
		break;
	    case TELQUAL_SEND:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "SEND");
		break;
	    default:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "- unknown qualifier %d (0x%x).",
			 pointer[1], pointer[1]);
	    }
	    nfrontp += strlen(nfrontp);
	    break;

	case TELOPT_NEW_ENVIRON:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "NEW-ENVIRON ");
	    goto env_common1;
	case TELOPT_OLD_ENVIRON:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "OLD-ENVIRON");
	env_common1:
	    nfrontp += strlen(nfrontp);
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "IS ");
		goto env_common;
	    case TELQUAL_SEND:
		snprintf(nfrontp,
			BUFSIZ - (nfrontp - netobuf),
			"SEND ");
		goto env_common;
	    case TELQUAL_INFO:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "INFO ");
	    env_common:
		nfrontp += strlen(nfrontp);
		{
		    int noquote = 2;
		    for (i = 2; i < length; i++ ) {
			switch (pointer[i]) {
			case NEW_ENV_VAR:
			    snprintf(nfrontp,
				     BUFSIZ - (nfrontp - netobuf),
				     "\" VAR " + noquote);
			    nfrontp += strlen(nfrontp);
			    noquote = 2;
			    break;

			case NEW_ENV_VALUE:
			    snprintf(nfrontp,
				     BUFSIZ - (nfrontp - netobuf),
				     "\" VALUE " + noquote);
			    nfrontp += strlen(nfrontp);
			    noquote = 2;
			    break;

			case ENV_ESC:
			    snprintf(nfrontp,
				     BUFSIZ - (nfrontp - netobuf),
				     "\" ESC " + noquote);
			    nfrontp += strlen(nfrontp);
			    noquote = 2;
			    break;

			case ENV_USERVAR:
			    snprintf(nfrontp,
				     BUFSIZ - (nfrontp - netobuf),
				     "\" USERVAR " + noquote);
			    nfrontp += strlen(nfrontp);
			    noquote = 2;
			    break;

			default:
			    if (isprint(pointer[i]) && pointer[i] != '"') {
				if (noquote) {
				    *nfrontp++ = '"';
				    noquote = 0;
				}
				*nfrontp++ = pointer[i];
			    } else {
				snprintf(nfrontp,
					 BUFSIZ - (nfrontp - netobuf),
					 "\" %03o " + noquote,
					 pointer[i]);
				nfrontp += strlen(nfrontp);
				noquote = 2;
			    }
			    break;
			}
		    }
		    if (!noquote)
			*nfrontp++ = '"';
		    break;
		}
	    }
	    break;

#if	defined(AUTHENTICATION)
	case TELOPT_AUTHENTICATION:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "AUTHENTICATION");
	    nfrontp += strlen(nfrontp);

	    if (length < 2) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " (empty suboption??\?)");
		nfrontp += strlen(nfrontp);
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_REPLY:
	    case TELQUAL_IS:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " %s ",
			 (pointer[1] == TELQUAL_IS) ?
				"IS" : "REPLY");
		nfrontp += strlen(nfrontp);
		if (AUTHTYPE_NAME_OK(pointer[2]))
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "%s ",
			     AUTHTYPE_NAME(pointer[2]));
		else
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "%d ",
			     pointer[2]);
		nfrontp += strlen(nfrontp);
		if (length < 3) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "(partial suboption??\?)");
		    nfrontp += strlen(nfrontp);
		    break;
		}
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s|%s",
			 ((pointer[3] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT) ?
			 "CLIENT" : "SERVER",
			 ((pointer[3] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) ?
			 "MUTUAL" : "ONE-WAY");
		nfrontp += strlen(nfrontp);

		auth_printsub(&pointer[1], length - 1, buf, sizeof(buf));
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s",
			 buf);
		nfrontp += strlen(nfrontp);
		break;

	    case TELQUAL_SEND:
		i = 2;
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " SEND ");
		nfrontp += strlen(nfrontp);
		while (i < length) {
		    if (AUTHTYPE_NAME_OK(pointer[i]))
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%s ",
				 AUTHTYPE_NAME(pointer[i]));
		    else
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%d ",
				 pointer[i]);
		    nfrontp += strlen(nfrontp);
		    if (++i >= length) {
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "(partial suboption??\?)");
			nfrontp += strlen(nfrontp);
			break;
		    }
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "%s|%s ",
			((pointer[i] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT) ?
							"CLIENT" : "SERVER",
			((pointer[i] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) ?
							"MUTUAL" : "ONE-WAY");
		    nfrontp += strlen(nfrontp);
		    ++i;
		}
		break;

	    case TELQUAL_NAME:
		i = 2;
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " NAME \"");
		nfrontp += strlen(nfrontp);
		while (i < length)
		    *nfrontp++ = pointer[i++];
		*nfrontp++ = '"';
		break;

	    default:
		    for (i = 2; i < length; i++) {
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 " ?%d?",
				 pointer[i]);
			nfrontp += strlen(nfrontp);
		    }
		    break;
	    }
	    break;
#endif

#if	defined(ENCRYPTION)
	case TELOPT_ENCRYPT:
	    snprintf(nfrontp,
		     BUFSIZ - (nfrontp - netobuf),
		     "ENCRYPT");
	    nfrontp += strlen(nfrontp);
	    if (length < 2) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " (empty suboption?)");
		nfrontp += strlen(nfrontp);
		break;
	    }
	    switch (pointer[1]) {
	    case ENCRYPT_START:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " START");
		nfrontp += strlen(nfrontp);
		break;

	    case ENCRYPT_END:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " END");
		nfrontp += strlen(nfrontp);
		break;

	    case ENCRYPT_REQSTART:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " REQUEST-START");
		nfrontp += strlen(nfrontp);
		break;

	    case ENCRYPT_REQEND:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " REQUEST-END");
		nfrontp += strlen(nfrontp);
		break;

	    case ENCRYPT_IS:
	    case ENCRYPT_REPLY:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " %s ",
			 (pointer[1] == ENCRYPT_IS) ?
				"IS" : "REPLY");
		nfrontp += strlen(nfrontp);
		if (length < 3) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " (partial suboption?)");
		    nfrontp += strlen(nfrontp);
		    break;
		}
		if (ENCTYPE_NAME_OK(pointer[2]))
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     "%s ",
			     ENCTYPE_NAME(pointer[2]));
		else
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " %d (unknown)",
			     pointer[2]);
		nfrontp += strlen(nfrontp);

		encrypt_printsub(&pointer[1], length - 1, buf, sizeof(buf));
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s",
			 buf);
		nfrontp += strlen(nfrontp);
		break;

	    case ENCRYPT_SUPPORT:
		i = 2;
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " SUPPORT ");
		nfrontp += strlen(nfrontp);
		while (i < length) {
		    if (ENCTYPE_NAME_OK(pointer[i]))
			snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
				 "%s ",
				 ENCTYPE_NAME(pointer[i]));
		    else
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%d ",
				 pointer[i]);
		    nfrontp += strlen(nfrontp);
		    i++;
		}
		break;

	    case ENCRYPT_ENC_KEYID:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " ENC_KEYID %d",
			 pointer[1]);
		nfrontp += strlen(nfrontp);
		goto encommon;

	    case ENCRYPT_DEC_KEYID:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " DEC_KEYID %d",
			 pointer[1]);
		nfrontp += strlen(nfrontp);
		goto encommon;

	    default:
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " %d (unknown)",
			 pointer[1]);
		nfrontp += strlen(nfrontp);
	    encommon:
		for (i = 2; i < length; i++) {
		    snprintf(nfrontp,
			     BUFSIZ - (nfrontp - netobuf),
			     " %d",
			     pointer[i]);
		    nfrontp += strlen(nfrontp);
		}
		break;
	    }
	    break;
#endif

	default:
	    if (TELOPT_OK(pointer[0]))
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s (unknown)",
			 TELOPT(pointer[0]));
	    else
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%d (unknown)",
			 pointer[i]);
	    nfrontp += strlen(nfrontp);
	    for (i = 1; i < length; i++) {
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " %d",
			 pointer[i]);
		nfrontp += strlen(nfrontp);
	    }
	    break;
	}
	snprintf(nfrontp,
		 BUFSIZ - (nfrontp - netobuf),
		 "\r\n");
	nfrontp += strlen(nfrontp);
}

/*
 * Dump a data buffer in hex and ascii to the output data stream.
 */
	void
printdata(char *tag, char *ptr, int cnt)
{
	int i;
	char xbuf[30];

	while (cnt) {
		/* flush net output buffer if no room for new data) */
		if ((&netobuf[BUFSIZ] - nfrontp) < 80) {
			netflush();
		}

		/* add a line of output */
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 "%s: ",
			 tag);
		nfrontp += strlen(nfrontp);
		for (i = 0; i < 20 && cnt; i++) {
			snprintf(nfrontp,
				 BUFSIZ - (nfrontp - netobuf),
				 "%02x",
				 *ptr);
			nfrontp += strlen(nfrontp);
			if (isprint(*ptr)) {
				xbuf[i] = *ptr;
			} else {
				xbuf[i] = '.';
			}
			if (i % 2) {
				*nfrontp = ' ';
				nfrontp++;
			}
			cnt--;
			ptr++;
		}
		xbuf[i] = '\0';
		snprintf(nfrontp,
			 BUFSIZ - (nfrontp - netobuf),
			 " %s\r\n",
			 xbuf);
		nfrontp += strlen(nfrontp);
	}
}
#endif /* DIAGNOSTICS */
