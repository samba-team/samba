/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Kungliga Tekniska
 *      Högskolan and its contributors.
 * 
 * 4. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "kx.h"

RCSID("$Id$");

static int nchild;
static int donep;

/*
 * Signal handler that justs waits for the children when they die.
 */

static RETSIGTYPE
childhandler (int sig)
{
     pid_t pid;
     int status;

     do { 
	 pid = waitpid (-1, &status, WNOHANG|WUNTRACED);
	 if (pid > 0 && (WIFEXITED(status) || WIFSIGNALED(status)))
	     if (--nchild == 0 && donep)
		 exit (0);
     } while(pid > 0);
     signal (SIGCHLD, childhandler);
     SIGRETURN(0);
}

/*
 * Handler for SIGUSR1.
 * This signal means that we should wait until there are no children
 * left and then exit.
 */

static RETSIGTYPE
usr1handler (int sig)
{
    donep = 1;

    SIGRETURN(0);
}

/*
 * Almost the same as for SIGUSR1, except we should exit immediately
 * if there are no active children.
 */

static RETSIGTYPE
usr2handler (int sig)
{
    donep = 1;
    if (nchild == 0)
	exit (0);

    SIGRETURN(0);
}

/*
 * Establish authenticated connection
 */

static int
connect_host (char *host, char *user, des_cblock *key,
	      des_key_schedule schedule, int port,
	      struct sockaddr_in *thisaddr,
	      struct sockaddr_in *thataddr)
{
     CREDENTIALS cred;
     KTEXT_ST text;
     MSG_DAT msg;
     int status;
     int addrlen;
     struct hostent *hostent;
     int s;
     char **p;

     hostent = gethostbyname (host);
     if (hostent == NULL) {
	 warnx ("gethostbyname '%s' failed: %s", host,
		hstrerror(h_errno));
	 return -1;
     }

     memset (thataddr, 0, sizeof(*thataddr));
     thataddr->sin_family = AF_INET;
     thataddr->sin_port   = port;
     for(p = hostent->h_addr_list; *p; ++p) {
	 memcpy (&thataddr->sin_addr, *p, sizeof(thataddr->sin_addr));

	 s = socket (AF_INET, SOCK_STREAM, 0);
	 if (s < 0)
	     err (1, "socket");

	 if (connect (s, (struct sockaddr *)thataddr, sizeof(*thataddr)) < 0) {
	     warn ("connect(%s)", host);
	     close (s);
	     continue;
	 } else {
	     break;
	 }
     }
     if (*p == NULL)
	 return -1;

     addrlen = sizeof(*thisaddr);
     if (getsockname (s, (struct sockaddr *)thisaddr, &addrlen) < 0 ||
	 addrlen != sizeof(*thisaddr))
	 err(1, "getsockname(%s)", host);
     status = krb_sendauth (KOPT_DO_MUTUAL, s, &text, "rcmd",
			    host, krb_realmofhost (host),
			    getpid(), &msg, &cred, schedule,
			    thisaddr, thataddr, KX_VERSION);
     if (status != KSUCCESS) {
	 warnx ("%s: %s\n", host, krb_get_err_text(status));
	 return -1;
     }
     memcpy(key, cred.session, sizeof(des_cblock));
     return s;
}

/*
 * Get rid of the cookie that we were sent and get the correct one
 * from our own cookie file instead.
 */

static int
passive_session (int xserver, int fd, des_cblock *iv,
		 des_key_schedule schedule)
{
    if (replace_cookie (xserver, fd, XauFileName(), 1))
	return 1;
    else
	return copy_encrypted (xserver, fd, iv, schedule);
}

static int
active_session (int xserver, int fd, des_cblock *iv,
		des_key_schedule schedule)
{
    if (verify_and_remove_cookies (xserver, fd, 1))
	return 1;
    else
	return copy_encrypted (xserver, fd, iv, schedule);
}

static void
status_output (int debugp)
{
    if(debugp)
	printf ("%u\t%s\t%s\n", (unsigned)getpid(), display, xauthfile);
    else {
	pid_t pid;
	
	pid = fork();
	if (pid < 0) {
	    err(1, "fork");
	} else if (pid > 0) {
	    printf ("%u\t%s\t%s\n", (unsigned)pid, display, xauthfile);
	    exit (0);
	} else {
	    fclose(stdout);
	}
    }
}

/*
 * Obtain an authenticated connection to `host' on `port'.  Send a kx
 * message saying we are `user' and want to use passive mode.  Wait
 * for answer on that connection and fork of a child for every new
 * connection we have to make.
 */

static int
doit_passive (char *host, char *user, int debugp, int keepalivep,
	      int port)
{
     des_key_schedule schedule;
     des_cblock key;
     int otherside;
     struct sockaddr_in me, him;
     u_char msg[1024], *p;
     int len;
     void *ret;
     u_int32_t tmp;

     otherside = connect_host (host, user, &key, schedule, port,
			       &me, &him);
     if (otherside < 0)
	 return 1;
#if defined(SO_KEEPALIVE) && defined(HAVE_SETSOCKOPT)
     if (keepalivep) {
	 int one = 1;

	 setsockopt (otherside, SOL_SOCKET, SO_KEEPALIVE, (void *)&one,
		     sizeof(one));
     }
#endif

     p = msg;
     *p++ = INIT;
     len = strlen(user);
     p += krb_put_int (len, p, sizeof(msg) - 1, 4);
     memcpy(p, user, len);
     p += len;
     *p++ = PASSIVE | (keepalivep ? KEEP_ALIVE : 0);
     if (write_encrypted (otherside, msg, p - msg, schedule,
			  &key, &me, &him) < 0)
	 err (1, "write to %s", host);
     len = read_encrypted (otherside, msg, sizeof(msg), &ret,
			   schedule, &key, &him, &me);
     if (len <= 0)
	 errx (1,
	       "error reading initial message from %s: "
	       "this probably means it's using an old version.",
	       host);
     p = (u_char *)ret;
     if (*p == ERROR) {
	 p++;
	 p += krb_get_int (p, &tmp, 4, 0);
	 errx (1, "%s: %.*s", host, (int)tmp, p);
     } else if (*p != ACK) {
	 errx (1, "%s: strange msg %d", host, *p);
     } else
	 p++;
     p += krb_get_int (p, &tmp, 4, 0);
     memcpy(display, p, tmp);
     display[tmp] = '\0';
     p += tmp;

     p += krb_get_int (p, &tmp, 4, 0);
     memcpy(xauthfile, p, tmp);
     xauthfile[tmp] = '\0';
     p += tmp;

     status_output (debugp);
     for (;;) {
	 pid_t child;

	 len = read_encrypted (otherside, msg, sizeof(msg), &ret,
			       schedule, &key, &him, &me);
	 if (len < 0)
	     err (1, "read from %s", host);
	 else if (len == 0)
	     return 0;

	 p = (u_char *)ret;
	 if (*p == ERROR) {
	     p++;
	     p += krb_get_int (p, &tmp, 4, 0);
	     errx (1, "%s: %.*s", host, (int)tmp, p);
	 } else if(*p != NEW_CONN) {
	     errx (1, "%s: strange msg %d", host, *p);
	 } else {
	     p++;
	     p += krb_get_int (p, &tmp, 4, 0);
	 }
	 
	 ++nchild;
	 child = fork ();
	 if (child < 0) {
	     warn("fork");
	     continue;
	 } else if (child == 0) {
	     struct sockaddr_in addr;
	     int fd;
	     int xserver;

	     addr = him;
	     close (otherside);

	     addr.sin_port = htons(tmp);
	     fd = socket (AF_INET, SOCK_STREAM, 0);
	     if (fd < 0)
		 err(1, "socket");
#if defined(TCP_NODELAY) && defined(HAVE_SETSOCKOPT)
	     {
		 int one = 1;

		 setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (void *)&one,
			     sizeof(one));
	     }
#endif
#if defined(SO_KEEPALIVE) && defined(HAVE_SETSOCKOPT)
	     if (keepalivep) {
		 int one = 1;

		 setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&one,
			     sizeof(one));
	     }
#endif

	     if (connect (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		 err(1, "connect(%s)", host);
	     {
		 int d = 0;
		 char *s;

		 s = getenv ("DISPLAY");
		 if (s != NULL) {
		     s = strchr (s, ':');
		     if (s != NULL)
			 d = atoi (s + 1);
		 }

		 xserver = connect_local_xsocket (d);
		 if (xserver < 0)
		     return 1;
	     }
	     return passive_session (xserver, fd, &key, schedule);
	 } else {
	 }
     }
}

/*
 * Allocate a local pseudo-xserver and wait for connections 
 */

static int
doit_active (char *host, char *user,
	     int debugpp, int keepalivep, int tcpp, int port)
{
    des_key_schedule schedule;
    des_cblock key;
    int otherside;
    int nsockets;
    struct x_socket *sockets;
    struct sockaddr_in me, him;
    u_char msg[1024], *p;
    int len = strlen(user);
    void *ret;
    int tmp, tmp2;
    char *s;
    int i;
    size_t rem;
    u_int32_t other_port;

    otherside = connect_host (host, user, &key, schedule, port,
			      &me, &him);
    if (otherside < 0)
	return 1;
#if defined(SO_KEEPALIVE) && defined(HAVE_SETSOCKOPT)
    if (keepalivep) {
	int one = 1;

	setsockopt (otherside, SOL_SOCKET, SO_KEEPALIVE, (void *)&one,
		    sizeof(one));
    }
#endif
    p = msg;
    rem = sizeof(msg);
    *p++ = INIT;
    --rem;
    len = strlen(user);
    tmp = krb_put_int (len, p, rem, 4);
    if (tmp < 0)
	return 1;
    p += tmp;
    rem -= tmp;
    memcpy(p, user, len);
    p += len;
    rem -= len;
    *p++ = (keepalivep ? KEEP_ALIVE : 0);
    --rem;

    s = getenv("DISPLAY");
    if (s == NULL || (s = strchr(s, ':')) == NULL) 
	s = ":0";
    len = strlen (s);
    tmp = krb_put_int (len, p, rem, 4);
    if (tmp < 0)
	return 1;
    rem -= tmp;
    p += tmp;
    memcpy (p, s, len);
    p += len;
    rem -= len;

    s = getenv("XAUTHORITY");
    if (s == NULL)
	s = "";
    len = strlen (s);
    tmp = krb_put_int (len, p, rem, 4);
    if (tmp < 0)
	return 1;
    p += len;
    rem -= len;
    memcpy (p, s, len);
    p += len;
    rem -= len;

    if (write_encrypted (otherside, msg, p - msg, schedule,
			 &key, &me, &him) < 0)
	err (1, "write to %s", host);

    len = read_encrypted (otherside, msg, sizeof(msg), &ret,
			  schedule, &key, &him, &me);
    if (len < 0)
	err (1, "read from %s", host);
    p = (u_char *)ret;
    if (*p == ERROR) {
	u_int32_t u32;

	p++;
	p += krb_get_int (p, &u32, 4, 0);
	errx (1, "%s: %.*s", host, (int)u32, p);
    } else if (*p != ACK) {
	errx (1, "%s: strange msg %d", host, *p);
    } else
	p++;

    tmp2 = get_xsockets (&nsockets, &sockets, tcpp);
    if (tmp2 < 0)
	return 1;
    display_num = tmp2;
    if (tcpp)
	snprintf (display, display_size, "localhost:%u", display_num);
    else
	snprintf (display, display_size, ":%u", display_num);
    if (create_and_write_cookie (xauthfile, xauthfile_size, cookie, cookie_len))
	return 1;
    status_output (debugpp);
    for (;;) {
	fd_set fdset;
	pid_t child;
	int fd, thisfd = -1;
	int zero = 0;

	FD_ZERO(&fdset);
	for (i = 0; i < nsockets; ++i)
	    FD_SET(sockets[i].fd, &fdset);
	if (select(FD_SETSIZE, &fdset, NULL, NULL, NULL) <= 0)
	    continue;
	for (i = 0; i < nsockets; ++i)
	    if (FD_ISSET(sockets[i].fd, &fdset)) {
		thisfd = sockets[i].fd;
		break;
	    }
	fd = accept (thisfd, NULL, &zero);
	if (fd < 0) {
	    if (errno == EINTR)
		continue;
	    else
		err(1, "accept");
	}

	p = msg;
	*p++ = NEW_CONN;
	if (write_encrypted (otherside, msg, p - msg, schedule,
			     &key, &me, &him) < 0)
	    err (1, "write to %s", host);
	len = read_encrypted (otherside, msg, sizeof(msg), &ret,
			      schedule, &key, &him, &me);
	if (len < 0)
	    err (1, "read from %s", host);
	p = (u_char *)ret;
	if (*p == ERROR) {
	    u_int32_t val;

	    p++;
	    p += krb_get_int (p, &val, 4, 0);
	    errx (1, "%s: %.*s", host, (int)val, p);
	} else if (*p != NEW_CONN) {
	    errx (1, "%s: strange msg %d", host, *p);
	} else {
	    p++;
	    p += krb_get_int (p, &other_port, 4, 0);
	}

	++nchild;
	child = fork ();
	if (child < 0) {
	    warn("fork");
	    continue;
	} else if (child == 0) {
	    int s;
	    struct sockaddr_in addr;

	    for (i = 0; i < nsockets; ++i)
		close (sockets[i].fd);

	    addr = him;
	    close (otherside);

	    addr.sin_port = htons(other_port);
	    s = socket (AF_INET, SOCK_STREAM, 0);
	    if (s < 0)
		err(1, "socket");
#if defined(TCP_NODELAY) && defined(HAVE_SETSOCKOPT)
	    {
		int one = 1;

		setsockopt (s, IPPROTO_TCP, TCP_NODELAY, (void *)&one,
			    sizeof(one));
	    }
#endif
#if defined(SO_KEEPALIVE) && defined(HAVE_SETSOCKOPT)
	    if (keepalivep) {
		int one = 1;

		setsockopt (s, SOL_SOCKET, SO_KEEPALIVE, (void *)&one,
			    sizeof(one));
	    }
#endif

	    if (connect (s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		err(1, "connect");

	    return active_session (fd, s, &key, schedule);
	} else {
	    close (fd);
	}
    }
}

/*
 *
 */

static int
check_for_passive (const char *disp)
{
    char local_hostname[MaxHostNameLen];

    gethostname (local_hostname, sizeof(local_hostname));

    return disp != NULL &&
	(*disp == ':'
	 || strncmp(disp, "unix", 4) == 0
	 || strncmp(disp, "localhost", 9) == 0
	 || strncmp(disp, local_hostname, strlen(local_hostname)) == 0);
}

static void
usage(void)
{
    fprintf(stderr, "Usage: %s [-p port] [-d] [-D] [-t] [-l remoteuser] host\n",
	    __progname);
    exit (1);
}

/*
 * kx - forward x connection over a kerberos-encrypted channel.
 *
 */

int
main(int argc, char **argv)
{
     int force_passive = 0;
     int keepalivep = 1;
     char *user = NULL;
     int debugp = 0, tcpp = 0;
     int c;
     int port = 0;

     set_progname (argv[0]);
     while((c = getopt(argc, argv, "ktdDl:p:P")) != EOF) {
	 switch(c) {
	 case 'd' :
	     debugp = 1;
	     break;
	 case 'D':
	     krb_enable_debug();
	     break;
	 case 'k':
	     keepalivep = 0;
	     break;
	 case 't' :
	     tcpp = 1;
	     break;
	 case 'l' :
	     user = optarg;
	     break;
	 case 'p' :
	     port = htons(atoi (optarg));
	     break;
	 case 'P' :
	     force_passive = 1;
	     break;
	 case '?':
	 default:
	     usage();
	 }
     }

     argc -= optind;
     argv += optind;

     if (argc != 1)
	  usage ();
     if (user == NULL) {
	  struct passwd *p = k_getpwuid (getuid ());
	  if (p == NULL)
	      errx(1, "Who are you?");
	  user = strdup (p->pw_name);
	  if (user == NULL)
	      errx (1, "strdup: out of memory");
     }
     if (port == 0)
	 port = k_getportbyname ("kx", "tcp", htons(KX_PORT));
     signal (SIGCHLD, childhandler);
     signal (SIGUSR1, usr1handler);
     signal (SIGUSR2, usr2handler);
     if (force_passive || check_for_passive(getenv("DISPLAY")))
	 return doit_passive (argv[0], user, debugp, keepalivep, port);
     else
	 return doit_active  (argv[0], user, debugp, keepalivep, tcpp, port);
}
