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
     } while(pid > 0);
     signal (SIGCHLD, childhandler);
     SIGRETURN(0);
}

static void
fatal(int, des_cblock *, des_key_schedule,
      struct sockaddr_in *, struct sockaddr_in *,
      char *format, ...)
#ifdef __GNUC__
__attribute__ ((format (printf, 6, 7)))
#endif
;

static void
fatal (int fd, des_cblock *key, des_key_schedule schedule,
       struct sockaddr_in *thisaddr,
       struct sockaddr_in *thataddr,
       char *format, ...)
{
    u_char msg[1024];
    u_char *p;
    va_list args;
    int len;

    va_start(args, format);
    p = msg;
    *p++ = ERROR;
    vsnprintf (p + 4, sizeof(msg) - 5, format, args);
    syslog (LOG_ERR, p + 4);
    len = strlen (p + 4);
    p += krb_put_int (len, p, 4, 4);
    p += len;
    write_encrypted (fd, msg, p - msg, schedule, key, thisaddr, thataddr);
    va_end(args);
    exit (1);
}

static void
cleanup(int nsockets, struct x_socket *sockets)
{
    int i;

    if(xauthfile[0])
	unlink(xauthfile);
    for (i = 0; i < nsockets; ++i) {
	if (sockets[i].pathname != NULL) {
	    unlink (sockets[i].pathname);
	    free (sockets[i].pathname);
	}
    }
}

static int
recv_conn (int sock, des_cblock *key, des_key_schedule schedule,
	   struct sockaddr_in *thisaddr,
	   struct sockaddr_in *thataddr,
	   int *dispnr,
	   int *nsockets,
	   struct x_socket **sockets,
	   int tcpp)
{
     int status;
     KTEXT_ST ticket;
     AUTH_DAT auth;
     char user[ANAME_SZ];
     char instance[INST_SZ];
     int addrlen;
     char version[KRB_SENDAUTH_VLEN + 1];
     struct passwd *passwd;
     char remotehost[MaxHostNameLen];
     void *ret;
     int len;
     u_char msg[1024], *p;
     u_int32_t tmp32;
     int tmp;
     int flags;

     addrlen = sizeof(*thisaddr);
     if (getsockname (sock, (struct sockaddr *)thisaddr, &addrlen) < 0 ||
	 addrlen != sizeof(*thisaddr)) {
	 syslog (LOG_ERR, "getsockname: %m");
	 exit (1);
     }
     addrlen = sizeof(*thataddr);
     if (getpeername (sock, (struct sockaddr *)thataddr, &addrlen) < 0 ||
	 addrlen != sizeof(*thataddr)) {
	 syslog (LOG_ERR, "getpeername: %m");
	 exit (1);
     }

     inaddr2str (thataddr->sin_addr, remotehost, sizeof(remotehost));

     k_getsockinst (sock, instance, sizeof(instance));
     status = krb_recvauth (KOPT_DO_MUTUAL, sock, &ticket, "rcmd", instance,
			    thataddr, thisaddr, &auth, "", schedule,
			    version);
     if (status != KSUCCESS) {
	 syslog (LOG_ERR, "krb_recvauth: %s",
		 krb_get_err_text(status));
	 exit(1);
     }
     if( strncmp(version, KX_VERSION, KRB_SENDAUTH_VLEN) != 0) {
	 /* Try to be nice to old kx's */
	 if (strncmp (version, KX_OLD_VERSION, KRB_SENDAUTH_VLEN) == 0) {
	     char *old_errmsg = "\001Old version of kx. Please upgrade.";

	     syslog (LOG_ERR, "Old version client (%s)", version);

	     krb_net_read (sock, user, sizeof(user));
	     krb_net_write (sock, old_errmsg, strlen(old_errmsg) + 1);
	     exit (1);
	 }

	 fatal(sock, key, schedule, thisaddr, thataddr,
	       "Bad version %s", version);
     }
     memcpy(key, &auth.session, sizeof(des_cblock));

     len = read_encrypted (sock, msg, sizeof(msg), &ret,
			   schedule, key, thataddr, thisaddr);
     if (len < 0)
	 return 1;
     p = (u_char *)ret;
     if (*p != INIT)
	 fatal(sock, key, schedule, thisaddr, thataddr,
	       "Bad message");
     p++;
     p += krb_get_int (p, &tmp32, 4, 0);
     len = min(sizeof(user), tmp32);
     memcpy (user, p, len);
     p += tmp32;
     user[len] = '\0';

     passwd = k_getpwnam (user);
     if (passwd == NULL)
	  fatal (sock, key, schedule, thisaddr, thataddr,
		 "Cannot find uid");
     if (kuserok(&auth, user) != 0)
	  fatal (sock, key, schedule, thisaddr, thataddr,
		 "%s is not allowed to login as %s",
		 krb_unparse_name_long (auth.pname,
					auth.pinst,
					auth.prealm),
		 user);

     flags = *p++;

     if (flags & PASSIVE) {
	 pid_t pid;

	 tmp = get_xsockets (nsockets, sockets, tcpp);
	 if (tmp < 0) {
	     fatal (sock, key, schedule, thisaddr, thataddr,
		    "Cannot create X socket(s): %s",
		    strerror(errno));
	 }
	 *dispnr = tmp;

	 if (chown_xsockets (*nsockets, *sockets,
			    passwd->pw_uid, passwd->pw_gid)) {
	     cleanup (*nsockets, *sockets);
	     fatal (sock, key, schedule, thisaddr, thataddr,
		    "Cannot chown sockets: %s",
		    strerror(errno));
	 }

	 pid = fork();
	 if (pid == -1) {
	     cleanup (*nsockets, *sockets);
	     fatal (sock, key, schedule, thisaddr, thataddr,
		    "fork: %s", strerror(errno));
	 } else if (pid != 0) {
	     int status;

	     while (waitpid (pid, &status, 0) != pid
		    && !WIFEXITED(status)
		    && !WIFSIGNALED(status))
		 ;
	     cleanup (*nsockets, *sockets);
	     exit (0);
	 }
     }

     if (setgid (passwd->pw_gid) ||
	 initgroups(passwd->pw_name, passwd->pw_gid) ||
	 setuid(passwd->pw_uid)) {
	 fatal (sock, key, schedule, thisaddr, thataddr,
		"Cannot set uid");
     }
     syslog (LOG_INFO, "from %s(%s): %s -> %s",
	     remotehost,
	     inet_ntoa(thataddr->sin_addr),
	     krb_unparse_name_long (auth.pname, auth.pinst, auth.prealm),
	     user);
     umask(077);
     if (!(flags & PASSIVE)) {
	 p += krb_get_int (p, &tmp32, 4, 0);
	 len = min(tmp32, display_size);
	 memcpy (display, p, len);
	 display[len] = '\0';
	 p += tmp32;
	 p += krb_get_int (p, &tmp32, 4, 0);
	 len = min(tmp32, xauthfile_size);
	 memcpy (xauthfile, p, len);
	 xauthfile[len] = '\0';
	 p += tmp32;
     }
#if defined(SO_KEEPALIVE) && defined(HAVE_SETSOCKOPT)
     if (flags & KEEP_ALIVE) {
	 int one = 1;

	 setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&one,
		     sizeof(one));
     }
#endif
     return flags;
}

/*
 *
 */

static int
passive_session (int fd, int sock, int cookiesp, des_cblock *key,
		 des_key_schedule schedule)
{
    if (verify_and_remove_cookies (fd, sock, cookiesp))
	return 1;
    else
	return copy_encrypted (fd, sock, key, schedule);
}

static int
active_session (int fd, int sock, int cookiesp, des_cblock *key,
		des_key_schedule schedule)
{
    fd = connect_local_xsocket(0);

    if (replace_cookie (fd, sock, xauthfile, cookiesp))
	return 1;
    else
	return copy_encrypted (fd, sock, key, schedule);
}

static int
doit_conn (int fd, int meta_sock, int flags, int cookiesp,
	   des_cblock *key, des_key_schedule schedule,
	   struct sockaddr_in *thisaddr,
	   struct sockaddr_in *thataddr)
{
    int sock, sock2;
    struct sockaddr_in addr;
    int addrlen;
    u_char msg[1024], *p;

    sock = socket (AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
	syslog (LOG_ERR, "socket: %m");
	return 1;
    }
#if defined(TCP_NODELAY) && defined(HAVE_SETSOCKOPT)
    {
	int one = 1;
	setsockopt (sock, IPPROTO_TCP, TCP_NODELAY, (void *)&one, sizeof(one));
    }
#endif
#if defined(SO_KEEPALIVE) && defined(HAVE_SETSOCKOPT)
     if (flags & KEEP_ALIVE) {
	 int one = 1;

	 setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&one,
		     sizeof(one));
     }
#endif
    memset (&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (bind (sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	syslog (LOG_ERR, "bind: %m");
	return 1;
    }
    addrlen = sizeof(addr);
    if (getsockname (sock, (struct sockaddr *)&addr,
		     &addrlen) < 0) {
	syslog (LOG_ERR, "getsockname: %m");
	return 1;
    }
    if (listen (sock, SOMAXCONN) < 0) {
	syslog (LOG_ERR, "listen: %m");
	return 1;
    }
    p = msg;
    *p++ = NEW_CONN;
    p += krb_put_int (ntohs(addr.sin_port), p, 4, 4);

    if (write_encrypted (meta_sock, msg, p - msg, schedule, key,
			 thisaddr, thataddr) < 0) {
	syslog (LOG_ERR, "write: %m");
	return 1;
    }

    sock2 = accept (sock, (struct sockaddr *)thisaddr, &addrlen);
    if (sock2 < 0) {
	syslog (LOG_ERR, "accept: %m");
	return 1;
    }
    close (sock);
    close (meta_sock);

    if (flags & PASSIVE)
	return passive_session (fd, sock2, cookiesp, key, schedule);
    else
	return active_session (fd, sock2, cookiesp, key, schedule);
}

/*
 *
 */

static void
check_user_console (int fd, des_cblock *key, des_key_schedule schedule,
		    struct sockaddr_in *thisaddr,
		    struct sockaddr_in *thataddr)
{
     struct stat sb;

     if (stat ("/dev/console", &sb) < 0)
	 fatal (fd, key, schedule, thisaddr, thataddr,
		"Cannot stat /dev/console");
     if (getuid() != sb.st_uid)
	 fatal (fd, key, schedule, thisaddr, thataddr,
		"Permission denied");
}

/*
 * Handle a passive session on `sock'
 */

static int
doit_passive (int sock, des_cblock *key, des_key_schedule schedule,
	      struct sockaddr_in *me, struct sockaddr_in *him, int flags,
	      int displaynr, int nsockets, struct x_socket *sockets,
	      int tcpp)
{
    int tmp;
    int len;
    size_t rem;
    u_char msg[1024], *p;
    int error;

    display_num = displaynr;
    if (tcpp)
	snprintf (display, display_size, "localhost:%u", display_num);
    else
	snprintf (display, display_size, ":%u", display_num);
    error = create_and_write_cookie (xauthfile, xauthfile_size, 
				     cookie, cookie_len);
    if (error) {
	cleanup(nsockets, sockets);
	fatal (sock, key, schedule, me, him,
	       "Cookie-creation failed with: %s",
	       strerror(error));
	return 1;
    }

    p = msg;
    rem = sizeof(msg);
    *p++ = ACK;
    --rem;

    len = strlen (display);
    tmp = krb_put_int (len, p, rem, 4);
    if (tmp < 0 || rem < len + 4) {
	syslog (LOG_ERR, "doit: buffer too small");
	cleanup(nsockets, sockets);
	return 1;
    }
    p += tmp;
    rem -= tmp;

    memcpy (p, display, len);
    p += len;
    rem -= len;

    len = strlen (xauthfile);
    tmp = krb_put_int (len, p, rem, 4);
    if (tmp < 0 || rem < len + 4) {
	syslog (LOG_ERR, "doit: buffer too small");
	cleanup(nsockets, sockets);
	return 1;
    }
    p += tmp;
    rem -= tmp;

    memcpy (p, xauthfile, len);
    p += len;
    rem -= len;
	  
    if(write_encrypted (sock, msg, p - msg, schedule, key,
			me, him) < 0) {
	syslog (LOG_ERR, "write: %m");
	cleanup(nsockets, sockets);
	return 1;
    }
    for (;;) {
	pid_t child;
	int fd = -1;
	fd_set fds;
	int i;
	int ret;
	int cookiesp = TRUE;
	       
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	for (i = 0; i < nsockets; ++i)
	    FD_SET(sockets[i].fd, &fds);
	ret = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
	if(ret <= 0)
	    continue;
	if(FD_ISSET(sock, &fds)){
	    /* there are no processes left on the remote side
	     */
	    cleanup(nsockets, sockets);
	    exit(0);
	} else if(ret) {
	    for (i = 0; i < nsockets; ++i) {
		if (FD_ISSET(sockets[i].fd, &fds)) {
		    if (sockets[i].flags == TCP) {
			struct sockaddr_in peer;
			int len = sizeof(peer);

			fd = accept (sockets[i].fd,
				     (struct sockaddr *)&peer,
				     &len);
			if (fd < 0 && errno != EINTR)
			    syslog (LOG_ERR, "accept: %m");

			/* XXX */
			if (fd >= 0 && suspicious_address (fd, peer)) {
			    close (fd);
			    fd = -1;
			    errno = EINTR;
			}
		    } else if(sockets[i].flags == UNIX_SOCKET) {
			int zero = 0;

			fd = accept (sockets[i].fd, NULL, &zero);

			if (fd < 0 && errno != EINTR)
			    syslog (LOG_ERR, "accept: %m");
#ifdef MAY_HAVE_X11_PIPES
		    } else if(sockets[i].flags == STREAM_PIPE) {
			/*
			 * this code tries to handle the
			 * send fd-over-pipe stuff for
			 * solaris
			 */

			struct strrecvfd strrecvfd;

			ret = ioctl (sockets[i].fd,
				     I_RECVFD, &strrecvfd);
			if (ret < 0 && errno != EINTR) {
			    syslog (LOG_ERR, "ioctl I_RECVFD: %m");
			}

			/* XXX */
			if (ret == 0) {
			    if (strrecvfd.uid != getuid()) {
				close (strrecvfd.fd);
				fd = -1;
				errno = EINTR;
			    } else {
				fd = strrecvfd.fd;
				cookiesp = FALSE;
			    }
			}
#endif /* MAY_HAVE_X11_PIPES */
		    } else
			abort ();
		    break;
		}
	    }
	}
	if (fd < 0) {
	    if (errno == EINTR)
		continue;
	    else
		return 1;
	}

	child = fork ();
	if (child < 0) {
	    syslog (LOG_ERR, "fork: %m");
	    return 1;
	} else if (child == 0) {
	    for (i = 0; i < nsockets; ++i)
		close (sockets[i].fd);
	    return doit_conn (fd, sock, flags, cookiesp,
			      key, schedule, me, him);
	} else {
	    close (fd);
	}
    }
}

/*
 * Handle an active session on `sock'
 */

static int
doit_active (int sock, des_cblock *key, des_key_schedule schedule,
	     struct sockaddr_in *me, struct sockaddr_in *him,
	     int flags, int tcpp)
{
    u_char msg[1024], *p;

    check_user_console (sock, key, schedule, me, him);

    p = msg;
    *p++ = ACK;
	  
    if(write_encrypted (sock, msg, p - msg, schedule, key,
			me, him) < 0) {
	syslog (LOG_ERR, "write: %m");
	return 1;
    }
    for (;;) {
	pid_t child;
	int len;
	void *ret;
	      
	len = read_encrypted (sock, msg, sizeof(msg), &ret,
			      schedule, key,
			      him, me);
	if (len < 0) {
	    syslog (LOG_ERR, "read: %m");
	    return 1;
	}
	p = (u_char *)ret;
	if (*p != NEW_CONN) {
	    syslog (LOG_ERR, "bad_message: %d", *p);
	    return 1;
	}

	child = fork ();
	if (child < 0) {
	    syslog (LOG_ERR, "fork: %m");
	    return 1;
	} else if (child == 0) {
	    return doit_conn (sock, sock, flags, 1,
			      key, schedule, me, him);
	} else {
	}
    }
}

/*
 * Receive a connection on `sock' and process it.
 */

static int
doit(int sock, int tcpp)
{
     des_key_schedule schedule;
     des_cblock key;
     struct sockaddr_in me, him;
     int flags;
     struct x_socket *sockets;
     int nsockets;
     int dispnr;

     flags = recv_conn (sock, &key, schedule, &me, &him,
			&dispnr, &nsockets, &sockets, tcpp);

     if (flags & PASSIVE)
	 return doit_passive (sock, &key, schedule, &me, &him, flags,
			      dispnr, nsockets, sockets, tcpp);
     else
	 return doit_active (sock, &key, schedule, &me, &him, flags, tcpp);
}

static void
usage (void)
{
     fprintf (stderr, "Usage: %s [-i] [-t] [-p port]\n", __progname);
     exit (1);
}

/*
 * kxd - receive a forwarded X conncection
 */

int
main (int argc, char **argv)
{
     int c;
     int no_inetd = 0;
     int tcpp = 0;
     int port = 0;

     set_progname (argv[0]);

     while( (c = getopt (argc, argv, "itp:")) != EOF) {
	  switch (c) {
	  case 'i':
	       no_inetd = 1;
	       break;
	  case 't':
	       tcpp = 1;
	       break;
	  case 'p':
	      port = htons(atoi (optarg));
	      break;
	  case '?':
	  default:
	       usage ();
	  }
     }

     if (no_inetd)
	  mini_inetd (port ? port : k_getportbyname("kx", "tcp",
						    htons(KX_PORT)));
     roken_openlog(__progname, LOG_PID|LOG_CONS, LOG_DAEMON);
     signal (SIGCHLD, childhandler);
     return doit(STDIN_FILENO, tcpp);
}
