/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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
    p += krb_put_int (len, p, 4);
    p += len;
    write_encrypted (fd, msg, p - msg, schedule, key, thisaddr, thataddr);
    va_end(args);
    exit (1);
}

static void
cleanup(void)
{
    if(xauthfile[0])
	unlink(xauthfile);
    if(x_socket[0])
	unlink(x_socket);
}

static int
recv_conn (int sock, des_cblock *key, des_key_schedule schedule,
	   struct sockaddr_in *thisaddr,
	   struct sockaddr_in *thataddr)
{
     int status;
     KTEXT_ST ticket;
     AUTH_DAT auth;
     char user[ANAME_SZ + 1];
     char instance[INST_SZ + 1];
     int addrlen;
     char version[KRB_SENDAUTH_VLEN + 1];
     struct passwd *passwd;
     char remotehost[MaxHostNameLen];
     void *ret;
     int len;
     u_char msg[1024], *p;
     u_int32_t tmp;
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
     p += krb_get_int (p, &tmp, 4, 0);
     len = min(sizeof(user), tmp);
     strncpy (user, p, len);
     p += tmp;
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
     flags = *p++;
     if (!(flags & PASSIVE)) {
	 p += krb_get_int (p, &tmp, 4, 0);
	 len = min(tmp, display_size);
	 strncpy (display, p, len);
	 display[len] = '\0';
	 p += tmp;
	 p += krb_get_int (p, &tmp, 4, 0);
	 len = min(tmp, xauthfile_size);
	 strncpy (xauthfile, p, len);
	 p += tmp;
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
passive_session (int fd, int sock, des_cblock *key,
		 des_key_schedule schedule)
{
    if (verify_and_remove_cookies (fd, sock))
	return 1;
    else
	return copy_encrypted (fd, sock, key, schedule);
}

static int
active_session (int fd, int sock, des_cblock *key,
		des_key_schedule schedule)
{
    fd = connect_local_xsocket(0);

    if (replace_cookie (fd, sock, xauthfile))
	return 1;
    else
	return copy_encrypted (fd, sock, key, schedule);
}

static int
doit_conn (int fd, int meta_sock, int flags,
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
    p += krb_put_int (ntohs(addr.sin_port), p, 4);

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
	return passive_session (fd, sock2, key, schedule);
    else
	return active_session (fd, sock2, key, schedule);
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
 * Receive a connection on `sock' and process it.
 */

static int
doit(int sock, int tcpp)
{
     des_key_schedule schedule;
     des_cblock key;
     int localx, tcpx;
     struct sockaddr_in me, him;
     int flags;
     u_char msg[1024], *p;

     flags = recv_conn (sock, &key, schedule, &me, &him);

     if (flags & PASSIVE) {
	  int tmp;
	  int len;

	  tmp = get_xsockets (&localx, tcpp ? &tcpx : NULL);
	  if (tmp < 0)
	       return 1;
	  display_num = tmp;
	  if (tcpp)
	       snprintf (display, display_size, "localhost:%u", display_num);
	  else
	       snprintf (display, display_size, ":%u", display_num);
	  if(create_and_write_cookie (xauthfile, xauthfile_size, 
				      cookie, cookie_len)) {
             syslog(LOG_ERR, "create_and_write_cookie: %m");
             fatal (sock, &key, schedule, &me, &him,
                    "Cookie-creation failed with: %s",
		    strerror(errno));
             cleanup();
	     return 1;
	  }

	  p = msg;
	  *p++ = ACK;
	  len = strlen (display);
	  p += krb_put_int (len, p, 4);
	  strncpy (p, display, len);
	  p += len;
	  len = strlen (xauthfile);
	  p += krb_put_int (len, p, 4);
	  strncpy (p, xauthfile, len);
	  p += len;
	  
	  if(write_encrypted (sock, msg, p - msg, schedule, &key,
			      &me, &him) < 0) {
	      syslog (LOG_ERR, "write: %m");
	      cleanup();
	      return 1;
	  }
	  for (;;) {
	       pid_t child;
	       int fd;
	       int zero = 0;
	       fd_set fds;
	       
	       FD_ZERO(&fds);
	       FD_SET(localx, &fds);
	       FD_SET(sock, &fds);
	       if (tcpp)
		    FD_SET(tcpx, &fds);
	       if(select(FD_SETSIZE, &fds, NULL, NULL, NULL) <=0)
		   continue;
	       if(FD_ISSET(sock, &fds)){
		   /* there are no processes left on the remote side
		    */
		   cleanup();
		   exit(0);
	       } else if(FD_ISSET(localx, &fds))
		   fd = accept (localx, NULL, &zero);
	       else if(tcpp && FD_ISSET(tcpx, &fds)) {
		   struct sockaddr_in peer;
		   int len = sizeof(peer);

		   fd = accept (tcpx, (struct sockaddr *)&peer, &len);
		   /* XXX */
		   if (fd >= 0 && suspicious_address (fd, peer)) {
		       close (fd);
		       continue;
		   }
	       } else
		   continue;
	       if (fd < 0)
		    if (errno == EINTR)
			 continue;
		    else {
			syslog (LOG_ERR, "accept: %m");
			return 1;
		    }

	       child = fork ();
	       if (child < 0) {
		   syslog (LOG_ERR, "fork: %m");
		   return 1;
	       } else if (child == 0) {
		    close (localx);
		    if (tcpp)
			 close (tcpx);
		    return doit_conn (fd, sock, flags,
				      &key, schedule, &me, &him);
	       } else {
		    close (fd);
	       }
	  }
     } else {
	  check_user_console (sock, &key, schedule, &me, &him);

	  p = msg;
	  *p++ = ACK;
	  
	  if(write_encrypted (sock, msg, p - msg, schedule, &key,
			      &me, &him) < 0) {
	      syslog (LOG_ERR, "write: %m");
	      return 1;
	  }
	  for (;;) {
	      pid_t child;
	      int len;
	      void *ret;
	      
	      len = read_encrypted (sock, msg, sizeof(msg), &ret,
				    schedule, &key,
				    &him, &me);
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
		  return doit_conn (localx, sock, flags,
				    &key, schedule, &me, &him);
	      } else {
	      }
	  }
     }
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
     openlog(__progname, LOG_PID|LOG_CONS, LOG_DAEMON);
     signal (SIGCHLD, childhandler);
     return doit(STDIN_FILENO, tcpp);
}
