/*	$NetBSD: ftpd.c,v 1.15 1995/06/03 22:46:47 mycroft Exp $	*/

/*
 * Copyright (c) 1985, 1988, 1990, 1992, 1993, 1994
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

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

/*
 * FTP server.
 */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#define	FTP_NAMES
#include <arpa/ftp.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <pwd.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>

#include <stdarg.h>

#include "pathnames.h"
#include "extern.h"
#include "common.h"

#include "auth.h"

#include <krb.h>
#include <kafs.h>
#include "roken.h"

#if defined(SKEY)
#include <skey.h>
#endif

void yyparse();

extern char *optarg;
extern int optind, opterr;

#ifndef LOG_FTP
#define LOG_FTP LOG_DAEMON
#endif

#ifndef LOG_DAEMON
#define openlog(id,option,facility) openlog((id),(option))
#endif

static char version[] = "Version 6.00";

extern	off_t restart_point;
extern	char cbuf[];

struct	sockaddr_in ctrl_addr;
struct	sockaddr_in data_source;
struct	sockaddr_in data_dest;
struct	sockaddr_in his_addr;
struct	sockaddr_in pasv_addr;

int	data;
jmp_buf	errcatch, urgcatch;
int	oobflag;
int	logged_in;
struct	passwd *pw;
int	debug;
int	timeout = 900;    /* timeout after 15 minutes of inactivity */
int	maxtimeout = 7200;/* don't allow idle time to be set beyond 2 hours */
int	logging;
int	guest;
int	dochroot;
int	type;
int	form;
int	stru;			/* avoid C keyword */
int	mode;
int	usedefault = 1;		/* for data transfers */
int	pdata = -1;		/* for passive mode */
int 	transflag;
off_t	file_size;
off_t	byte_count;
#if !defined(CMASK) || CMASK == 0
#undef CMASK
#define CMASK 027
#endif
int	defumask = CMASK;		/* default umask value */
char	tmpline[10240];
char	hostname[MaxHostNameLen];
char	remotehost[MaxHostNameLen];
static char ttyline[20];
char	*tty = ttyline;		/* for klogin */

/* Default level for security, 0 allow any kind of connection, 1 only
   authorized and anonymous connections, 2 only authorized */
static int auth_level = 1;

#ifdef sun
extern char *optarg;
extern int optind, opterr;

int fclose(FILE*);
char* crypt(char*, char*);
#endif

char *getusershell(void);

/*
 * Timeout intervals for retrying connections
 * to hosts that don't accept PORT cmds.  This
 * is a kludge, but given the problems with TCP...
 */
#define	SWAITMAX	90	/* wait at most 90 seconds */
#define	SWAITINT	5	/* interval between retries */

int	swaitmax = SWAITMAX;
int	swaitint = SWAITINT;

#ifdef HAVE_SETPROCTITLE
char	proctitle[BUFSIZ];	/* initial part of title */
#endif /* HAVE_SETPROCTITLE */

#define LOGCMD(cmd, file) \
	if (logging > 1) \
	    syslog(LOG_INFO,"%s %s%s", cmd, \
		*(file) == '/' ? "" : curdir(), file);
#define LOGCMD2(cmd, file1, file2) \
	 if (logging > 1) \
	    syslog(LOG_INFO,"%s %s%s %s%s", cmd, \
		*(file1) == '/' ? "" : curdir(), file1, \
		*(file2) == '/' ? "" : curdir(), file2);
#define LOGBYTES(cmd, file, cnt) \
	if (logging > 1) { \
		if (cnt == (off_t)-1) \
		    syslog(LOG_INFO,"%s %s%s", cmd, \
			*(file) == '/' ? "" : curdir(), file); \
		else \
		    syslog(LOG_INFO, "%s %s%s = %ld bytes", \
			cmd, (*(file) == '/') ? "" : curdir(), file, cnt); \
	}

static void	 ack (char *);
static void	 myoob (int);
static int	 checkuser (char *, char *);
static FILE	*dataconn (char *, off_t, char *);
static void	 dolog (struct sockaddr_in *);
static void	 end_login (void);
static FILE	*getdatasock (char *);
static char	*gunique (char *);
static void	 lostconn (int);
static int	 receive_data (FILE *, FILE *);
static void	 send_data (FILE *, FILE *, off_t);
static struct passwd * sk_getpwnam (char *);

static char *
curdir(void)
{
	static char path[MaxPathLen+1+1];	/* path + '/' + '\0' */

	if (getcwd(path, sizeof(path)-2) == NULL)
		return ("");
	if (path[1] != '\0')		/* special case for root dir. */
		strcat(path, "/");
	/* For guest account, skip / since it's chrooted */
	return (guest ? path+1 : path);
}

#ifndef LINE_MAX
#define LINE_MAX 1024
#endif

static void conn_wait(int port)
{
    int s, t;
    struct sockaddr_in sa;
    int one = 1;
    s = socket(AF_INET, SOCK_STREAM, 0);

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_port = port; /* in network byteorder */
    sa.sin_addr.s_addr = INADDR_ANY;
    bind(s, (struct sockaddr*)&sa, sizeof(sa));
    listen(s, 5);
    t = accept(s, NULL, 0);
    close(s);
    dup2(t, 0);
    dup2(t, 1);
    if(t > 2)
	close(t);
}

int
main(int argc, char **argv, char **envp)
{
	int addrlen, ch, on = 1, tos;
	char *cp, line[LINE_MAX];
	FILE *fd;

	int not_inetd = 0;
	int port;
	struct servent *sp;
	    
	char tkfile[1024];

	/* detach from any tickets and tokens */

	sprintf(tkfile, "/tmp/ftp_%d", getpid());
	krb_set_tkt_string(tkfile);
	if(k_hasafs())
	    k_setpag();

	sp = getservbyname("ftp", "tcp");
	if(sp)
	    port = sp->s_port;
	else
	    port = htons(21);

	while ((ch = getopt(argc, argv, "a:dilp:t:T:u:v")) != EOF) {
		switch (ch) {
		case 'a':
		{
		    if(strcmp(optarg, "none") == 0)
			auth_level = 0;
		    else if(strcmp(optarg, "safe") == 0)
			auth_level = 1;
		    else if(strcmp(optarg, "user") == 0)
			auth_level = 2;
		    else
			warnx("bad value for -a");
		    break;
		}
		case 'd':
			debug = 1;
			break;

		case 'i':
		    not_inetd = 1;
		    break;
		case 'l':
			logging++;	/* > 1 == extra logging */
			break;

		case 'p':
		    sp = getservbyname(optarg, "tcp");
		    if(sp)
			port = sp->s_port;
		    else
			if(isdigit(optarg[0]))
			    port = htons(atoi(optarg));
			else
			    warnx("bad value for -p");
		    break;
		    
		case 't':
			timeout = atoi(optarg);
			if (maxtimeout < timeout)
				maxtimeout = timeout;
			break;

		case 'T':
			maxtimeout = atoi(optarg);
			if (timeout > maxtimeout)
				timeout = maxtimeout;
			break;

		case 'u':
		    {
			long val = 0;

			val = strtol(optarg, &optarg, 8);
			if (*optarg != '\0' || val < 0)
				warnx("bad value for -u");
			else
				defumask = val;
			break;
		    }

		case 'v':
			debug = 1;
			break;

		default:
                        warnx("unknown flag -%c ignored", argv[optind-1][0]);
			break;
		}
	}

	if(not_inetd)
	    conn_wait(port);


	/*
	 * LOG_NDELAY sets up the logging connection immediately,
	 * necessary for anonymous ftp's that chroot and can't do it later.
	 */
	openlog("ftpd", LOG_PID | LOG_NDELAY, LOG_FTP);
	addrlen = sizeof(his_addr);
	if (getpeername(0, (struct sockaddr *)&his_addr, &addrlen) < 0) {
		syslog(LOG_ERR, "getpeername (%s): %m",argv[0]);
		exit(1);
	}
	addrlen = sizeof(ctrl_addr);
	if (getsockname(0, (struct sockaddr *)&ctrl_addr, &addrlen) < 0) {
		syslog(LOG_ERR, "getsockname (%s): %m",argv[0]);
		exit(1);
	}
#ifdef IP_TOS
	tos = IPTOS_LOWDELAY;
	if (setsockopt(0, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int)) < 0)
		syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
	data_source.sin_port = htons(ntohs(ctrl_addr.sin_port) - 1);
	debug = 0;

	/* set this here so klogin can use it... */
	(void)sprintf(ttyline, "ftp%d", getpid());


	/*	(void) freopen(_PATH_DEVNULL, "w", stderr); */
	(void) signal(SIGPIPE, lostconn);
	(void) signal(SIGCHLD, SIG_IGN);
	if ((long)signal(SIGURG, myoob) < 0)
		syslog(LOG_ERR, "signal: %m");

	auth_init();

	/* Try to handle urgent data inline */
#ifdef SO_OOBINLINE
	if (setsockopt(0, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof(on)) < 0)
		syslog(LOG_ERR, "setsockopt: %m");
#endif

#ifdef	F_SETOWN
	if (fcntl(fileno(stdin), F_SETOWN, getpid()) == -1)
		syslog(LOG_ERR, "fcntl F_SETOWN: %m");
#endif
	dolog(&his_addr);
	/*
	 * Set up default state
	 */
	data = -1;
	type = TYPE_A;
	form = FORM_N;
	stru = STRU_F;
	mode = MODE_S;
	tmpline[0] = '\0';

	/* If logins are disabled, print out the message. */
	if ((fd = fopen(_PATH_NOLOGIN,"r")) != NULL) {
		while (fgets(line, sizeof(line), fd) != NULL) {
			if ((cp = strchr(line, '\n')) != NULL)
				*cp = '\0';
			lreply(530, "%s", line);
		}
		(void) fflush(stdout);
		(void) fclose(fd);
		reply(530, "System not available.");
		exit(0);
	}
	if ((fd = fopen(_PATH_FTPWELCOME, "r")) != NULL) {
		while (fgets(line, sizeof(line), fd) != NULL) {
			if ((cp = strchr(line, '\n')) != NULL)
				*cp = '\0';
			lreply(220, "%s", line);
		}
		(void) fflush(stdout);
		(void) fclose(fd);
		/* reply(220,) must follow */
	}
	(void) gethostname(hostname, sizeof(hostname));
	reply(220, "%s FTP server (%s) ready.", hostname, version);
	(void) setjmp(errcatch);
	for (;;)
		(void) yyparse();
	/* NOTREACHED */
}

static void
lostconn(int signo)
{

	if (debug)
		syslog(LOG_DEBUG, "lost connection");
	dologout(-1);
}

/*
 * Helper function for sgetpwnam().
 */
static char *
sgetsave(char *s)
{
	char *new = malloc((unsigned) strlen(s) + 1);

	if (new == NULL) {
		perror_reply(421, "Local resource failure: malloc");
		dologout(1);
		/* NOTREACHED */
	}
	(void) strcpy(new, s);
	return (new);
}

/*
 * Save the result of a getpwnam.  Used for USER command, since
 * the data returned must not be clobbered by any other command
 * (e.g., globbing).
 */
static struct passwd *
sgetpwnam(char *name)
{
	static struct passwd save;
	struct passwd *p;

	if ((p = k_getpwnam(name)) == NULL)
		return (p);
	if (save.pw_name) {
		free(save.pw_name);
		free(save.pw_passwd);
		free(save.pw_gecos);
		free(save.pw_dir);
		free(save.pw_shell);
	}
	save = *p;
	save.pw_name = sgetsave(p->pw_name);
	save.pw_passwd = sgetsave(p->pw_passwd);
	save.pw_gecos = sgetsave(p->pw_gecos);
	save.pw_dir = sgetsave(p->pw_dir);
	save.pw_shell = sgetsave(p->pw_shell);
	return (&save);
}

static int login_attempts;	/* number of failed login attempts */
static int askpasswd;		/* had user command, ask for passwd */
static char curname[10];	/* current USER name */
#ifdef SKEY
static struct skey sk;
static int permit_passwd;
#endif /* SKEY */

/*
 * USER command.
 * Sets global passwd pointer pw if named account exists and is acceptable;
 * sets askpasswd if a PASS command is expected.  If logged in previously,
 * need to reset state.  If name is "ftp" or "anonymous", the name is not in
 * _PATH_FTPUSERS, and ftp account exists, set guest and pw, then just return.
 * If account doesn't exist, ask for passwd anyway.  Otherwise, check user
 * requesting login privileges.  Disallow anyone who does not have a standard
 * shell as returned by getusershell().  Disallow anyone mentioned in the file
 * _PATH_FTPUSERS to allow people such as root and uucp to be avoided.
 */
void
user(char *name)
{
	char *cp, *shell;

	if(auth_level == 2 && !auth_complete){
	    reply(530, "No login allowed without authorization.");
	    return;
	}

	if (logged_in) {
		if (guest) {
			reply(530, "Can't change user from guest login.");
			return;
		} else if (dochroot) {
			reply(530, "Can't change user from chroot user.");
			return;
		}
		end_login();
	}

	guest = 0;
	if (strcmp(name, "ftp") == 0 || strcmp(name, "anonymous") == 0) {
	    if (checkuser(_PATH_FTPUSERS, "ftp") ||
		checkuser(_PATH_FTPUSERS, "anonymous"))
		reply(530, "User %s access denied.", name);
	    else if ((pw = sgetpwnam("ftp")) != NULL) {
		guest = 1;
		askpasswd = 1;
		reply(331, "Guest login ok, type your name as password.");
	    } else
		reply(530, "User %s unknown.", name);
	    if (!askpasswd && logging)
		syslog(LOG_NOTICE,
		       "ANONYMOUS FTP LOGIN REFUSED FROM %s", remotehost);
	    return;
	}
	if(auth_level == 1 && !auth_complete){
	    reply(530, "Only authorized and anonymous login allowed.");
	    return;
	}
	if ((pw = sgetpwnam(name))) {
		if ((shell = pw->pw_shell) == NULL || *shell == 0)
			shell = _PATH_BSHELL;
		while ((cp = getusershell()) != NULL)
			if (strcmp(cp, shell) == 0)
				break;
		endusershell();

		if (cp == NULL || checkuser(_PATH_FTPUSERS, name)) {
			reply(530, "User %s access denied.", name);
			if (logging)
				syslog(LOG_NOTICE,
				    "FTP LOGIN REFUSED FROM %s, %s",
				    remotehost, name);
			pw = (struct passwd *) NULL;
			return;
		}
	}
	if (logging)
		strncpy(curname, name, sizeof(curname)-1);
	if(auth_ok())
		ct->userok(name);
	else {
#ifdef SKEY
		char ss[256];

		permit_passwd = skeyaccess(k_getpwnam (name), NULL,
					   remotehost, NULL);

		if (skeychallenge (&sk, name, ss) == 0) {
			reply (331, "Password [%s] for %s required.",
			       ss, name);
			askpasswd = 1;
		} else if (permit_passwd)
#endif
		{
			reply(331, "Password required for %s.", name);
			askpasswd = 1;
		}
	}
	/*
	 * Delay before reading passwd after first failed
	 * attempt to slow down passwd-guessing programs.
	 */
	if (login_attempts)
		sleep((unsigned) login_attempts);
}

/*
 * Check if a user is in the file "fname"
 */
static int
checkuser(char *fname, char *name)
{
	FILE *fd;
	int found = 0;
	char *p, line[BUFSIZ];

	if ((fd = fopen(fname, "r")) != NULL) {
		while (fgets(line, sizeof(line), fd) != NULL)
			if ((p = strchr(line, '\n')) != NULL) {
				*p = '\0';
				if (line[0] == '#')
					continue;
				if (strcmp(line, name) == 0) {
					found = 1;
					break;
				}
			}
		(void) fclose(fd);
	}
	return (found);
}

int do_login(int code, char *passwd)
{
        FILE *fd;
	login_attempts = 0;		/* this time successful */
	if (setegid((gid_t)pw->pw_gid) < 0) {
		reply(550, "Can't set gid.");
		return -1;
	}
	(void) initgroups(pw->pw_name, pw->pw_gid);

	/* open wtmp before chroot */
	logwtmp(ttyline, pw->pw_name, remotehost);
	logged_in = 1;

	dochroot = checkuser(_PATH_FTPCHROOT, pw->pw_name);
	if (guest) {
		/*
		 * We MUST do a chdir() after the chroot. Otherwise
		 * the old current directory will be accessible as "."
		 * outside the new root!
		 */
		if (chroot(pw->pw_dir) < 0 || chdir("/") < 0) {
			reply(550, "Can't set guest privileges.");
			return -1;
		}
	} else if (dochroot) {
		if (chroot(pw->pw_dir) < 0 || chdir("/") < 0) {
			reply(550, "Can't change root.");
			return -1;
		}
	} else if (chdir(pw->pw_dir) < 0) {
		if (chdir("/") < 0) {
			reply(530, "User %s: can't change directory to %s.",
			    pw->pw_name, pw->pw_dir);
			return -1;
		} else
			lreply(code, "No directory! Logging in with home=/");
	}
	if (seteuid((uid_t)pw->pw_uid) < 0) {
		reply(550, "Can't set uid.");
		return -1;
	}
	/*
	 * Display a login message, if it exists.
	 * N.B. reply(code,) must follow the message.
	 */
	if ((fd = fopen(_PATH_FTPLOGINMESG, "r")) != NULL) {
		char *cp, line[LINE_MAX];

		while (fgets(line, sizeof(line), fd) != NULL) {
			if ((cp = strchr(line, '\n')) != NULL)
				*cp = '\0';
			lreply(code, "%s", line);
		}
	}
	if (guest) {
		reply(code, "Guest login ok, access restrictions apply.");
#ifdef HAVE_SETPROCTITLE
		sprintf(proctitle, "%s: anonymous/%.*s", remotehost,
		    sizeof(proctitle) - sizeof(remotehost) -
		    sizeof(": anonymous/"), passwd);
		setproctitle(proctitle);
#endif /* HAVE_SETPROCTITLE */
		if (logging)
			syslog(LOG_INFO, "ANONYMOUS FTP LOGIN FROM %s, %s",
			    remotehost, passwd);
	} else {
		reply(code, "User %s logged in.", pw->pw_name);
#ifdef HAVE_SETPROCTITLE
		sprintf(proctitle, "%s: %s", remotehost, pw->pw_name);
		setproctitle(proctitle);
#endif /* HAVE_SETPROCTITLE */
		if (logging)
			syslog(LOG_INFO, "FTP LOGIN FROM %s as %s",
			    remotehost, pw->pw_name);
	}
	(void) umask(defumask);
	return 0;
}


/*
 * Terminate login as previous user, if any, resetting state;
 * used when USER command is given or login fails.
 */
static void
end_login(void)
{

	(void) seteuid((uid_t)0);
	if (logged_in)
		logwtmp(ttyline, "", "");
	pw = NULL;
	logged_in = 0;
	guest = 0;
	dochroot = 0;
}

void
pass(char *passwd)
{
	int rval;
	/* some clients insists on sending a password */
	if (logged_in && askpasswd == 0){
	     reply(230, "Dumpucko!");
	     return;
	}

	if (logged_in || askpasswd == 0) {
		reply(503, "Login with USER first.");
		return;
	}
	askpasswd = 0;
	if (!guest) {		/* "ftp" is only account allowed no password */
		if (pw == NULL) {
			rval = 1;	/* failure below */
			goto skip;
		}
#ifdef SKEY
		if (skeyverify (&sk, passwd) == 0) {
			rval = 0;
			goto skip;
		} else if(!permit_passwd) {
			rval = 1;
			goto skip;
		}
#endif
		rval = klogin(pw->pw_name, passwd);
		if (rval == 0)
			goto skip;

		/* the strcmp does not catch null passwords! */
		if (pw == NULL || *pw->pw_passwd == 0 ||
		    strcmp((char*)crypt(passwd, pw->pw_passwd), pw->pw_passwd)){
		    rval = 1;	 /* failure */
		    goto skip;
		}
		rval = 0;

skip:
		/*
		 * If rval == 1, the user failed the authentication check
		 * above.  If rval == 0, either Kerberos or local authentication
		 * succeeded.
		 */
		if (rval) {
			reply(530, "Login incorrect.");
			if (logging)
				syslog(LOG_NOTICE,
				    "FTP LOGIN FAILED FROM %s, %s",
				    remotehost, curname);
			pw = NULL;
			if (login_attempts++ >= 5) {
				syslog(LOG_NOTICE,
				    "repeated login failures from %s",
				    remotehost);
				exit(0);
			}
			return;
		}
	}
	if(!do_login(230, passwd))
	  return;
	
	/* Forget all about it... */
	end_login();
}

void
retrieve(char *cmd, char *name)
{
	FILE *fin, *dout;
	struct stat st;
	int (*closefunc) (FILE *);

	if (cmd == 0) {
		fin = fopen(name, "r"), closefunc = fclose;
		st.st_size = 0;
	} else {
		char line[BUFSIZ];

		(void) sprintf(line, cmd, name), name = line;
		fin = ftpd_popen(line, "r"), closefunc = ftpd_pclose;
		st.st_size = -1;
		st.st_blksize = BUFSIZ;
	}
	if (fin == NULL) {
		if (errno != 0) {
			perror_reply(550, name);
			if (cmd == 0) {
				LOGCMD("get", name);
			}
		}
		return;
	}
	byte_count = -1;
	if (cmd == 0 && (fstat(fileno(fin), &st) < 0 || !S_ISREG(st.st_mode))) {
		reply(550, "%s: not a plain file.", name);
		goto done;
	}
	if (restart_point) {
		if (type == TYPE_A) {
			off_t i, n;
			int c;

			n = restart_point;
			i = 0;
			while (i++ < n) {
				if ((c=getc(fin)) == EOF) {
					perror_reply(550, name);
					goto done;
				}
				if (c == '\n')
					i++;
			}
		} else if (lseek(fileno(fin), restart_point, SEEK_SET) < 0) {
			perror_reply(550, name);
			goto done;
		}
	}
	dout = dataconn(name, st.st_size, "w");
	if (dout == NULL)
		goto done;
	send_data(fin, dout, st.st_blksize);
	(void) fclose(dout);
	data = -1;
	pdata = -1;
done:
	if (cmd == 0)
		LOGBYTES("get", name, byte_count);
	(*closefunc)(fin);
}

/* filename sanity check */

static const char good_chars[] = "+-=_,.";

int 
filename_check(char *filename)
{
    char *p;

    p = strrchr(filename, '/');
    if(p)
	filename = p + 1;

    p = filename;

    if(isalnum(*p)){
	p++;
	while(*p && (isalnum(*p) || strchr(good_chars, *p)))
	    p++;
	if(*p == '\0')
	    return 0;
    }
    lreply(553, "\"%s\" is an illegal filename.", filename);
    lreply(553, "The filename must start with an alphanumeric "
	   "character and must only");
    reply(553, "consist of alphanumeric characters or any of the following: %s", 
	  good_chars);
    return 1;
}

void
store(char *name, char *mode, int unique)
{
	FILE *fout, *din;
	struct stat st;
	int (*closefunc) (FILE *);

	if(filename_check(name))
	    return;
	if (unique && stat(name, &st) == 0 &&
	    (name = gunique(name)) == NULL) {
		LOGCMD(*mode == 'w' ? "put" : "append", name);
		return;
	}

	if (restart_point)
		mode = "r+";
	fout = fopen(name, mode);
	closefunc = fclose;
	if (fout == NULL) {
		perror_reply(553, name);
		LOGCMD(*mode == 'w' ? "put" : "append", name);
		return;
	}
	byte_count = -1;
	if (restart_point) {
		if (type == TYPE_A) {
			off_t i, n;
			int c;

			n = restart_point;
			i = 0;
			while (i++ < n) {
				if ((c=getc(fout)) == EOF) {
					perror_reply(550, name);
					goto done;
				}
				if (c == '\n')
					i++;
			}
			/*
			 * We must do this seek to "current" position
			 * because we are changing from reading to
			 * writing.
			 */
			if (fseek(fout, 0L, SEEK_CUR) < 0) {
				perror_reply(550, name);
				goto done;
			}
		} else if (lseek(fileno(fout), restart_point, SEEK_SET) < 0) {
			perror_reply(550, name);
			goto done;
		}
	}
	din = dataconn(name, (off_t)-1, "r");
	if (din == NULL)
		goto done;
	if (receive_data(din, fout) == 0) {
		if (unique)
			reply(226, "Transfer complete (unique file name:%s).",
			    name);
		else
			reply(226, "Transfer complete.");
	}
	(void) fclose(din);
	data = -1;
	pdata = -1;
done:
	LOGBYTES(*mode == 'w' ? "put" : "append", name, byte_count);
	(*closefunc)(fout);
}

static FILE *
getdatasock(char *mode)
{
	int on = 1, s, t, tries;

	if (data >= 0)
		return (fdopen(data, mode));
	(void) seteuid((uid_t)0);
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		goto bad;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
	    (char *) &on, sizeof(on)) < 0)
		goto bad;
	/* anchor socket to avoid multi-homing problems */
	data_source.sin_family = AF_INET;
	data_source.sin_addr = ctrl_addr.sin_addr;
	for (tries = 1; ; tries++) {
		if (bind(s, (struct sockaddr *)&data_source,
		    sizeof(data_source)) >= 0)
			break;
		if (errno != EADDRINUSE || tries > 10)
			goto bad;
		sleep(tries);
	}
	(void) seteuid((uid_t)pw->pw_uid);
#ifdef IP_TOS
	on = IPTOS_THROUGHPUT;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&on, sizeof(int)) < 0)
		syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
	return (fdopen(s, mode));
bad:
	/* Return the real value of errno (close may change it) */
	t = errno;
	(void) seteuid((uid_t)pw->pw_uid);
	(void) close(s);
	errno = t;
	return (NULL);
}

static FILE *
dataconn(char *name, off_t size, char *mode)
{
	char sizebuf[32];
	FILE *file;
	int retry = 0, tos;

	file_size = size;
	byte_count = 0;
	if (size != (off_t) -1)
		(void) sprintf(sizebuf, " (%ld bytes)", size);
	else
		(void) strcpy(sizebuf, "");
	if (pdata >= 0) {
		struct sockaddr_in from;
		int s, fromlen = sizeof(from);

		s = accept(pdata, (struct sockaddr *)&from, &fromlen);
		if (s < 0) {
			reply(425, "Can't open data connection.");
			(void) close(pdata);
			pdata = -1;
			return (NULL);
		}
		(void) close(pdata);
		pdata = s;
#ifdef IP_TOS
		tos = IPTOS_THROUGHPUT;
		(void) setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&tos,
		    sizeof(int));
#endif
		reply(150, "Opening %s mode data connection for '%s'%s.",
		     type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
		return (fdopen(pdata, mode));
	}
	if (data >= 0) {
		reply(125, "Using existing data connection for '%s'%s.",
		    name, sizebuf);
		usedefault = 1;
		return (fdopen(data, mode));
	}
	if (usedefault)
		data_dest = his_addr;
	usedefault = 1;
	file = getdatasock(mode);
	if (file == NULL) {
		reply(425, "Can't create data socket (%s,%d): %s.",
		    inet_ntoa(data_source.sin_addr),
		    ntohs(data_source.sin_port), strerror(errno));
		return (NULL);
	}
	data = fileno(file);
	while (connect(data, (struct sockaddr *)&data_dest,
	    sizeof(data_dest)) < 0) {
		if (errno == EADDRINUSE && retry < swaitmax) {
			sleep((unsigned) swaitint);
			retry += swaitint;
			continue;
		}
		perror_reply(425, "Can't build data connection");
		(void) fclose(file);
		data = -1;
		return (NULL);
	}
	reply(150, "Opening %s mode data connection for '%s'%s.",
	     type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	return (file);
}

/*
 * Tranfer the contents of "instr" to "outstr" peer using the appropriate
 * encapsulation of the data subject * to Mode, Structure, and Type.
 *
 * NB: Form isn't handled.
 */
static void
send_data(FILE *instr, FILE *outstr, off_t blksize)
{
	int c, cnt, filefd, netfd;
	char *buf;
	int i = 0;
	char s[1024];

	transflag++;
	if (setjmp(urgcatch)) {
		transflag = 0;
		return;
	}
	switch (type) {

	case TYPE_A:
		while ((c = getc(instr)) != EOF) {
		    byte_count++;
		    if(i > 1022){
			auth_write(fileno(outstr), s, i);
			i = 0;
		    }
		    if(c == '\n')
			s[i++] = '\r';
		    s[i++] = c;
		}
		if(i)
		    auth_write(fileno(outstr), s, i);
		auth_write(fileno(outstr), s, 0);
		fflush(outstr);
		transflag = 0;
		if (ferror(instr))
			goto file_err;
		if (ferror(outstr))
			goto data_err;
		reply(226, "Transfer complete.");
		return;

	case TYPE_I:
	case TYPE_L:
		if ((buf = malloc((u_int)blksize)) == NULL) {
			transflag = 0;
			perror_reply(451, "Local resource failure: malloc");
			return;
		}
		netfd = fileno(outstr);
		filefd = fileno(instr);
		while ((cnt = read(filefd, buf, (u_int)blksize)) > 0 &&
		       auth_write(netfd, buf, cnt) == cnt)
		    byte_count += cnt;
		auth_write(netfd, buf, 0); /* to end an encrypted stream */
		transflag = 0;
		(void)free(buf);
		if (cnt != 0) {
			if (cnt < 0)
				goto file_err;
			goto data_err;
		}
		reply(226, "Transfer complete.");
		return;
	default:
		transflag = 0;
		reply(550, "Unimplemented TYPE %d in send_data", type);
		return;
	}

data_err:
	transflag = 0;
	perror_reply(426, "Data connection");
	return;

file_err:
	transflag = 0;
	perror_reply(551, "Error on input file");
}

/*
 * Transfer data from peer to "outstr" using the appropriate encapulation of
 * the data subject to Mode, Structure, and Type.
 *
 * N.B.: Form isn't handled.
 */
static int
receive_data(FILE *instr, FILE *outstr)
{
    int cnt, bare_lfs = 0;
    char buf[BUFSIZ];

    transflag++;
    if (setjmp(urgcatch)) {
	transflag = 0;
	return (-1);
    }
    switch (type) {

    case TYPE_I:
    case TYPE_L:
	while ((cnt = auth_read(fileno(instr), buf, sizeof(buf))) > 0) {
	    if (write(fileno(outstr), buf, cnt) != cnt)
		goto file_err;
	    byte_count += cnt;
	}
	if (cnt < 0)
	    goto data_err;
	transflag = 0;
	return (0);

    case TYPE_E:
	reply(553, "TYPE E not implemented.");
	transflag = 0;
	return (-1);

    case TYPE_A:
    {
	char *p, *q;
	int cr_flag = 0;
	while ((cnt = auth_read(fileno(instr), buf+cr_flag, 
				sizeof(buf)-cr_flag)) > 0){
	    byte_count += cnt;
	    cr_flag = 0;
	    for(p = buf, q = buf; p < buf + cnt;){
		if(*p == '\n')
		    bare_lfs++;
		if(*p == '\r')
		    if(p == buf + cnt - 1){
			cr_flag = 1;
			p++;
			continue;
		    }else if(p[1] == '\n'){
			*q++ = '\n';
			p += 2;
			continue;
		    }
		*q++ = *p++;
	    }
	    fwrite(buf, q - buf, 1, outstr);
	    if(cr_flag)
		buf[0] = '\r';
	}
	if(cr_flag)
	    putc('\r', outstr);
	fflush(outstr);
	if (ferror(instr))
	    goto data_err;
	if (ferror(outstr))
	    goto file_err;
	transflag = 0;
	if (bare_lfs) {
	    lreply(226, "WARNING! %d bare linefeeds received in ASCII mode\r\n"
		   "    File may not have transferred correctly.\r\n",
		   bare_lfs);
	}
	return (0);
    }
    default:
	reply(550, "Unimplemented TYPE %d in receive_data", type);
	transflag = 0;
	return (-1);
    }
	
data_err:
    transflag = 0;
    perror_reply(426, "Data Connection");
    return (-1);
	
file_err:
    transflag = 0;
    perror_reply(452, "Error writing file");
    return (-1);
}

void
statfilecmd(char *filename)
{
	FILE *fin;
	int c;
	char line[LINE_MAX];

	sprintf(line, "/bin/ls -lA %s", filename);
	fin = ftpd_popen(line, "r");
	lreply(211, "status of %s:", filename);
	while ((c = getc(fin)) != EOF) {
		if (c == '\n') {
			if (ferror(stdout)){
				perror_reply(421, "control connection");
				(void) ftpd_pclose(fin);
				dologout(1);
				/* NOTREACHED */
			}
			if (ferror(fin)) {
				perror_reply(551, filename);
				(void) ftpd_pclose(fin);
				return;
			}
			(void) putc('\r', stdout);
		}
		(void) putc(c, stdout);
	}
	(void) ftpd_pclose(fin);
	reply(211, "End of Status");
}

void
statcmd(void)
{
#if 0
	struct sockaddr_in *sin;
	u_char *a, *p;

	lreply(211, "%s FTP server status:", hostname, version);
	printf("     %s\r\n", version);
	printf("     Connected to %s", remotehost);
	if (!isdigit(remotehost[0]))
		printf(" (%s)", inet_ntoa(his_addr.sin_addr));
	printf("\r\n");
	if (logged_in) {
		if (guest)
			printf("     Logged in anonymously\r\n");
		else
			printf("     Logged in as %s\r\n", pw->pw_name);
	} else if (askpasswd)
		printf("     Waiting for password\r\n");
	else
		printf("     Waiting for user name\r\n");
	printf("     TYPE: %s", typenames[type]);
	if (type == TYPE_A || type == TYPE_E)
		printf(", FORM: %s", formnames[form]);
	if (type == TYPE_L)
#if NBBY == 8
		printf(" %d", NBBY);
#else
		printf(" %d", bytesize);	/* need definition! */
#endif
	printf("; STRUcture: %s; transfer MODE: %s\r\n",
	    strunames[stru], modenames[mode]);
	if (data != -1)
		printf("     Data connection open\r\n");
	else if (pdata != -1) {
		printf("     in Passive mode");
		sin = &pasv_addr;
		goto printaddr;
	} else if (usedefault == 0) {
		printf("     PORT");
		sin = &data_dest;
printaddr:
		a = (u_char *) &sin->sin_addr;
		p = (u_char *) &sin->sin_port;
#define UC(b) (((int) b) & 0xff)
		printf(" (%d,%d,%d,%d,%d,%d)\r\n", UC(a[0]),
			UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
#undef UC
	} else
		printf("     No data connection\r\n");
#endif
	reply(211, "End of status");
}

void
fatal(char *s)
{

	reply(451, "Error in server: %s\n", s);
	reply(221, "Closing connection due to server error.");
	dologout(0);
	/* NOTREACHED */
}

static void
int_reply(int n, char *c, const char *fmt, va_list ap)
{
  char buf[10240];
  char *p;
  p=buf;
  sprintf(p, "%d%s", n, c);
  p+=strlen(p);
  vsprintf(p, fmt, ap);
  p+=strlen(p);
  sprintf(p, "\r\n");
  p+=strlen(p);
  auth_printf("%s", buf);
  fflush(stdout);
  if (debug)
    syslog(LOG_DEBUG, "<--- %s- ", buf);
}

void
reply(int n, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int_reply(n, " ", fmt, ap);
  delete_ftp_command();
  va_end(ap);
}

void
lreply(int n, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int_reply(n, "-", fmt, ap);
  va_end(ap);
}

static void
ack(char *s)
{

	reply(250, "%s command successful.", s);
}

void
nack(char *s)
{

	reply(502, "%s command not implemented.", s);
}

/* ARGSUSED */
void
yyerror(char *s)
{
	char *cp;

	if ((cp = strchr(cbuf,'\n')))
		*cp = '\0';
	reply(500, "'%s': command not understood.", cbuf);
}

void
delete(char *name)
{
	struct stat st;

	LOGCMD("delete", name);
	if (stat(name, &st) < 0) {
		perror_reply(550, name);
		return;
	}
	if ((st.st_mode&S_IFMT) == S_IFDIR) {
		if (rmdir(name) < 0) {
			perror_reply(550, name);
			return;
		}
		goto done;
	}
	if (unlink(name) < 0) {
		perror_reply(550, name);
		return;
	}
done:
	ack("DELE");
}

void
cwd(char *path)
{

	if (chdir(path) < 0)
		perror_reply(550, path);
	else
		ack("CWD");
}

void
makedir(char *name)
{

	LOGCMD("mkdir", name);
	if(filename_check(name))
	    return;
	if (mkdir(name, 0777) < 0)
		perror_reply(550, name);
	else
		reply(257, "MKD command successful.");
}

void
removedir(char *name)
{

	LOGCMD("rmdir", name);
	if (rmdir(name) < 0)
		perror_reply(550, name);
	else
		ack("RMD");
}

void
pwd(void)
{
    char path[MaxPathLen + 1];
    char *ret;

    /* SunOS has a broken getcwd that does popen(pwd) (!!!), this
     * failes miserably when running chroot 
     */
    ret = getcwd(path, sizeof(path));
    if (ret == NULL)
	reply(550, "%s.", strerror(errno));
    else
	reply(257, "\"%s\" is current directory.", path);
}

char *
renamefrom(char *name)
{
	struct stat st;

	if (stat(name, &st) < 0) {
		perror_reply(550, name);
		return ((char *)0);
	}
	reply(350, "File exists, ready for destination name");
	return (name);
}

void
renamecmd(char *from, char *to)
{

	LOGCMD2("rename", from, to);
	if(filename_check(to))
	    return;
	if (rename(from, to) < 0)
		perror_reply(550, "rename");
	else
		ack("RNTO");
}

static void
dolog(struct sockaddr_in *sin)
{
	struct hostent *hp = gethostbyaddr((char *)&sin->sin_addr,
		sizeof(struct in_addr), AF_INET);

	if (hp)
		(void) strncpy(remotehost, hp->h_name, sizeof(remotehost));
	else
		(void) strncpy(remotehost, inet_ntoa(sin->sin_addr),
		    sizeof(remotehost));
#ifdef HAVE_SETPROCTITLE
	sprintf(proctitle, "%s: connected", remotehost);
	setproctitle(proctitle);
#endif /* HAVE_SETPROCTITLE */

	if (logging)
		syslog(LOG_INFO, "connection from %s", remotehost);
}

/*
 * Record logout in wtmp file
 * and exit with supplied status.
 */
void
dologout(int status)
{

	if (logged_in) {
		(void) seteuid((uid_t)0);
		logwtmp(ttyline, "", "");
		dest_tkt();
		if(k_hasafs())
		    k_unlog();
	}
	/* beware of flushing buffers after a SIGPIPE */
#ifdef XXX
	exit(status);
#else
	_exit(status);
#endif	
}

void abor(void)
{
}

static void
myoob(int signo)
{
#if 0
	char *cp;
#endif

	/* only process if transfer occurring */
	if (!transflag)
		return;

	oobflag = 1;
	yyparse();
	oobflag = 0;

	/* hopefully this will work. this way we can send commands to
           yyparse() from other sources than stdin */

#if 0 
	cp = tmpline;
	if (getline(cp, 7) == NULL) {
		reply(221, "You could at least say goodbye.");
		dologout(0);
	}
	upper(cp);
	if (strcmp(cp, "ABOR\r\n") == 0) {
		tmpline[0] = '\0';
		reply(426, "Transfer aborted. Data connection closed.");
		reply(226, "Abort successful");
		longjmp(urgcatch, 1);
	}
	if (strcmp(cp, "STAT\r\n") == 0) {
		if (file_size != (off_t) -1)
			reply(213, "Status: %ld of %ld bytes transferred",
			    byte_count, file_size);
		else
			reply(213, "Status: %ld bytes transferred", byte_count);
	}
#endif
}

/*
 * Note: a response of 425 is not mentioned as a possible response to
 *	the PASV command in RFC959. However, it has been blessed as
 *	a legitimate response by Jon Postel in a telephone conversation
 *	with Rick Adams on 25 Jan 89.
 */
void
passive(void)
{
	int len;
	char *p, *a;

	pdata = socket(AF_INET, SOCK_STREAM, 0);
	if (pdata < 0) {
		perror_reply(425, "Can't open passive connection");
		return;
	}
	pasv_addr = ctrl_addr;
	pasv_addr.sin_port = 0;
	(void) seteuid((uid_t)0);
	if (bind(pdata, (struct sockaddr *)&pasv_addr, sizeof(pasv_addr)) < 0) {
		(void) seteuid((uid_t)pw->pw_uid);
		goto pasv_error;
	}
	(void) seteuid((uid_t)pw->pw_uid);
	len = sizeof(pasv_addr);
	if (getsockname(pdata, (struct sockaddr *) &pasv_addr, &len) < 0)
		goto pasv_error;
	if (listen(pdata, 1) < 0)
		goto pasv_error;
	a = (char *) &pasv_addr.sin_addr;
	p = (char *) &pasv_addr.sin_port;

#define UC(b) (((int) b) & 0xff)

	reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", UC(a[0]),
		UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
	return;

pasv_error:
	(void) close(pdata);
	pdata = -1;
	perror_reply(425, "Can't open passive connection");
	return;
}

/*
 * Generate unique name for file with basename "local".
 * The file named "local" is already known to exist.
 * Generates failure reply on error.
 */
static char *
gunique(char *local)
{
	static char new[MaxPathLen];
	struct stat st;
	int count;
	char *cp;

	cp = strrchr(local, '/');
	if (cp)
		*cp = '\0';
	if (stat(cp ? local : ".", &st) < 0) {
		perror_reply(553, cp ? local : ".");
		return ((char *) 0);
	}
	if (cp)
		*cp = '/';
	(void) strcpy(new, local);
	cp = new + strlen(new);
	*cp++ = '.';
	for (count = 1; count < 100; count++) {
		(void)sprintf(cp, "%d", count);
		if (stat(new, &st) < 0)
			return (new);
	}
	reply(452, "Unique file name cannot be created.");
	return (NULL);
}

/*
 * Format and send reply containing system error number.
 */
void
perror_reply(int code, char *string)
{

	reply(code, "%s: %s.", string, strerror(errno));
}

static char *onefile[] = {
	"",
	0
};

void
send_file_list(char *whichf)
{
	struct stat st;
	DIR *dirp = NULL;
	struct dirent *dir;
	FILE *dout = NULL;
	char **dirlist, *dirname;
	int simple = 0;
	int freeglob = 0;
	glob_t gl;

	char buf[MaxPathLen];

	if (strpbrk(whichf, "~{[*?") != NULL) {
		int flags = GLOB_BRACE|GLOB_NOCHECK|GLOB_QUOTE|GLOB_TILDE;

		memset(&gl, 0, sizeof(gl));
		freeglob = 1;
		if (glob(whichf, flags, 0, &gl)) {
			reply(550, "not found");
			goto out;
		} else if (gl.gl_pathc == 0) {
			errno = ENOENT;
			perror_reply(550, whichf);
			goto out;
		}
		dirlist = gl.gl_pathv;
	} else {
		onefile[0] = whichf;
		dirlist = onefile;
		simple = 1;
	}

	if (setjmp(urgcatch)) {
		transflag = 0;
		goto out;
	}
	while ((dirname = *dirlist++)) {
		if (stat(dirname, &st) < 0) {
			/*
			 * If user typed "ls -l", etc, and the client
			 * used NLST, do what the user meant.
			 */
			if (dirname[0] == '-' && *dirlist == NULL &&
			    transflag == 0) {
				retrieve("/bin/ls %s", dirname);
				goto out;
			}
			perror_reply(550, whichf);
			if (dout != NULL) {
				(void) fclose(dout);
				transflag = 0;
				data = -1;
				pdata = -1;
			}
			goto out;
		}

		if (S_ISREG(st.st_mode)) {
			if (dout == NULL) {
				dout = dataconn("file list", (off_t)-1, "w");
				if (dout == NULL)
					goto out;
				transflag++;
			}
			sprintf(buf, "%s%s\n", dirname,
				type == TYPE_A ? "\r" : "");
			auth_write(fileno(dout), buf, strlen(buf));
			byte_count += strlen(dirname) + 1;
			continue;
		} else if (!S_ISDIR(st.st_mode))
			continue;

		if ((dirp = opendir(dirname)) == NULL)
			continue;

		while ((dir = readdir(dirp)) != NULL) {
			char nbuf[MaxPathLen];

			if (!strcmp(dir->d_name, "."))
				continue;
			if (!strcmp(dir->d_name, ".."))
				continue;

			sprintf(nbuf, "%s/%s", dirname, dir->d_name);

			/*
			 * We have to do a stat to insure it's
			 * not a directory or special file.
			 */
			if (simple || (stat(nbuf, &st) == 0 &&
				       S_ISREG(st.st_mode))) {
			    if (dout == NULL) {
				dout = dataconn("file list", (off_t)-1, "w");
				if (dout == NULL)
				    goto out;
				transflag++;
			    }
			    if(strncmp(nbuf, "./", 2) == 0)
				sprintf(buf, "%s%s\n", nbuf +2,
					type == TYPE_A ? "\r" : "");
			    else
				sprintf(buf, "%s%s\n", nbuf,
					type == TYPE_A ? "\r" : "");
			    auth_write(fileno(dout), buf, strlen(buf));
			    byte_count += strlen(nbuf) + 1;
			}
		}
		(void) closedir(dirp);
	}
	if (dout == NULL)
		reply(550, "No files found.");
	else if (ferror(dout) != 0)
		perror_reply(550, "Data connection");
	else
		reply(226, "Transfer complete.");

	transflag = 0;
	if (dout != NULL){
	    auth_write(fileno(dout), buf, 0); /* XXX flush */
	    
	    (void) fclose(dout);
	}
	data = -1;
	pdata = -1;
out:
	if (freeglob) {
		freeglob = 0;
		globfree(&gl);
	}
}
