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
 *
 *	@(#)telnetd.h	8.1 (Berkeley) 6/4/93
 */


#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/param.h>

#include <sys/socket.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#elif defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#else
#include <time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */
#ifndef	_CRAY
#include <sys/wait.h>
#endif	/* CRAY */
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

/* including both <sys/ioctl.h> and <termios.h> in SunOS 4 generates a
   lot of warnings */

#if defined(HAVE_SYS_IOCTL_H) && SunOS != 4
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#ifndef	LOG_DAEMON
#define	LOG_DAEMON	0
#endif
#ifndef	LOG_ODELAY
#define	LOG_ODELAY	0
#endif
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <termios.h>

#ifdef HAVE_PTY_H
#include <pty.h>
#endif

#include "defs.h"

#include <arpa/telnet.h>

#ifndef _POSIX_VDISABLE
# ifdef VDISABLE
#  define _POSIX_VDISABLE VDISABLE
# else
#  define _POSIX_VDISABLE ((unsigned char)'\377')
# endif
#endif


#ifdef	_CRAY
# ifdef	CRAY1
# include <sys/pty.h>
#  ifndef FD_ZERO
# include <sys/select.h>
#  endif /* FD_ZERO */
# endif	/* CRAY1 */

#include <memory.h>
#endif	/* _CRAY */

#ifdef __hpux
#include <sys/ptyio.h>
#endif

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif

#include "ext.h"
#include "pathnames.h"
#include <protos.h>

#ifdef SOCKS
#include <socks.h>
#endif

#ifdef KRB4
#include <des.h>
#include <krb.h>
#endif

#ifdef AUTHENTICATION
#include <libtelnet/auth.h>
#include <libtelnet/misc.h>
#ifdef ENCRYPTION
#include <libtelnet/encrypt.h>
#endif
#endif

#include <roken.h>

#ifdef	DIAGNOSTICS
#define	DIAG(a,b)	if (diagnostic & (a)) b
#else
#define	DIAG(a,b)
#endif

/* other external variables */
extern	char **environ;
extern	int errno;

/* prototypes */

/* appends data to nfrontp and advances */
int output_data (const char *format, ...)
#ifdef __GNUC__
__attribute__ ((format (printf, 1, 2)))
#endif
;
