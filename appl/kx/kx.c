/*
 * Copyright (c) 1995, 1996 Kungliga Tekniska Högskolan (Royal Institute
 * of Technology, Stockholm, Sweden).
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

char *prog;

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
	 if (pid > 0 && WIFEXITED(status) || WIFSIGNALED(status))
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
	      des_key_schedule schedule, int passivep, int port)
{
     CREDENTIALS cred;
     KTEXT_ST text;
     MSG_DAT msg;
     int status;
     struct sockaddr_in thisaddr, thataddr;
     int addrlen;
     struct hostent *hostent;
     int s;
     u_char b;
     char **p;
     char name[ANAME_SZ+1];

     hostent = gethostbyname (host);
     if (hostent == NULL) {
	  fprintf (stderr,
		   "%s: gethostbyname '%s' failed: %s\n", prog, host,
#ifdef HAVE_H_ERRNO
		   hstrerror(h_errno));
#else
		   "unknown error");
#endif
	  return -1;
     }

     memset (&thataddr, 0, sizeof(thataddr));
     thataddr.sin_family = AF_INET;
     thataddr.sin_port   = port;
     for(p = hostent->h_addr_list; *p; ++p) {
	 int one = 1;

	 memcpy (&thataddr.sin_addr, *p, sizeof(thataddr.sin_addr));

	 s = socket (AF_INET, SOCK_STREAM, 0);
	 if (s < 0) {
	     fprintf (stderr, "%s: socket failed: %s\n",
		      prog,
		      strerror(errno));
	     return -1;
	 }

#if defined(TCP_NODELAY) && defined(HAVE_SETSOCKOPT)
	 setsockopt (s, IPPROTO_TCP, TCP_NODELAY, (void *)&one, sizeof(one));
#endif

	 if (connect (s, (struct sockaddr *)&thataddr, sizeof(thataddr)) < 0) {
	     fprintf (stderr, "%s: connect(%s) failed: %s\n", prog, host,
		      strerror(errno));
	     close (s);
	     continue;
	 } else {
	     break;
	 }
     }
     if (*p == NULL)
	 return -1;

     addrlen = sizeof(thisaddr);
     if (getsockname (s, (struct sockaddr *)&thisaddr, &addrlen) < 0 ||
	 addrlen != sizeof(thisaddr)) {
	  fprintf (stderr, "%s: getsockname(%s) failed: %s\n",
		   prog, host, strerror(errno));
	  return -1;
     }
     status = krb_sendauth (KOPT_DO_MUTUAL, s, &text, "rcmd",
			    host, krb_realmofhost (host),
			    getpid(), &msg, &cred, schedule,
			    &thisaddr, &thataddr, KX_VERSION);
     if (status != KSUCCESS) {
	  fprintf (stderr, "%s: %s: %s\n", prog, host,
		   krb_get_err_text(status));
	  return -1;
     }

     memcpy(key, cred.session, sizeof(des_cblock));
     strncpy (name, user, sizeof(name));
     name[sizeof(name) - 1] = '\0';
     if (krb_net_write (s, name, sizeof(name)) != sizeof(name)) {
	  fprintf (stderr, "%s: write: %s\n", prog, strerror(errno));
	  return -1;
     }
     if (krb_net_read (s, &b, sizeof(b)) != sizeof(b)) {
	  fprintf (stderr, "%s: read: %s\n", prog,
		   strerror(errno));
	  return -1;
     }
     if (b) {
	  char buf[BUFSIZ];

	  krb_net_read (s, buf, sizeof(buf));
	  buf[BUFSIZ - 1] = '\0';

	  fprintf (stderr, "%s: %s: %s\n", prog, host, buf);
	  return -1;
     }
     b = passivep;
     if (krb_net_write (s, &b, sizeof(b)) != sizeof(b)) {
	  fprintf (stderr, "%s: write: %s\n", prog, strerror(errno));
	  return -1;
     }

     if (krb_net_read (s, display, display_size) != display_size) {
	  fprintf (stderr, "%s: read: %s\n", prog, strerror(errno));
	  return -1;
     }
     
     if (krb_net_read (s, xauthfile, xauthfile_size) != xauthfile_size) {
	  fprintf (stderr, "%s: read: %s\n", prog,
		   strerror(errno));
	  return -1;
     }

     return s;
}

/*
 * Get rid of the cookie that we were sent and get the correct one
 * from our own cookie file instead.
 */

static int
start_session(int xserver, int fd, des_cblock *iv,
	      des_key_schedule schedule)
{
     u_char beg[12];
     int bigendianp;
     unsigned n, d, npad, dpad;
     Xauth *auth;
     FILE *f;
     char *filename;
     u_char zeros[6] = {0, 0, 0, 0, 0, 0};

     if (krb_net_read (fd, beg, sizeof(beg)) != sizeof(beg))
	  return 1;
     if (krb_net_write (xserver, beg, 6) != 6)
	  return 1;
     bigendianp = beg[0] == 'B';
     if (bigendianp) {
	  n = (beg[6] << 8) | beg[7];
	  d = (beg[8] << 8) | beg[9];
     } else {
	  n = (beg[7] << 8) | beg[6];
	  d = (beg[9] << 8) | beg[8];
     }
     if (n != 0 || d != 0)
	  return 1;
     filename = XauFileName();
     if (filename == NULL)
	  return 1;
     f = fopen(filename, "r");
     if (f) {
	  u_char len[6] = {0, 0, 0, 0, 0, 0};

	  auth = XauReadAuth(f);
	  fclose(f);
	  n = auth->name_length;
	  d = auth->data_length;
	  if (bigendianp) {
	       len[0] = n >> 8;
	       len[1] = n & 0xFF;
	       len[2] = d >> 8;
	       len[3] = d & 0xFF;
	  } else {
	       len[0] = n & 0xFF;
	       len[1] = n >> 8;
	       len[2] = d & 0xFF;
	       len[3] = d >> 8;
	  }
	  if (krb_net_write (xserver, len, 6) != 6)
	       return 1;
	  if(krb_net_write (xserver, auth->name, n) != n)
	       return 1;
	  npad = (4 - (n % 4)) % 4;
	  if (npad) { 
	       if (krb_net_write (xserver, zeros, npad) != npad)
		    return 1;
	  }
	  if (krb_net_write (xserver, auth->data, d) != d)
	       return 1;
	  dpad = (4 - (d % 4)) % 4;
	  if (dpad) { 
	       if (krb_net_write (xserver, zeros, dpad) != dpad)
		    return 1;
	  }
	  XauDisposeAuth(auth);
     } else {
	  if(krb_net_write(xserver, zeros, 6) != 6)
	       return 1;
     }

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
	    fprintf (stderr, "%s: fork: %s\n", prog, strerror(errno));
	    exit (1);
	} else if (pid > 0) {
	    printf ("%u\t%s\t%s\n", (unsigned)pid, display, xauthfile);
	    exit (0);
	} else {
	    fclose(stdout);
	}
    }
}

/*
 *
 */

static int
doit_passive (char *host, char *user, int debugp, int port)
{
     des_key_schedule schedule;
     des_cblock key;
     int otherside;

     otherside = connect_host (host, user, &key, schedule, 1, port);
     if (otherside < 0)
	 return 1;
     status_output (debugp);
     for (;;) {
	 char tmp[6];
	 pid_t child;
	 int i;

	 i = krb_net_read (otherside, tmp, sizeof(tmp));
	 if (i < 0) {
	     fprintf (stderr, "%s: read: %s\n", prog, strerror(errno));
	     return 1;
	 } else if (i == 0)
	     return 0;
	 ++nchild;
	 child = fork ();
	 if (child < 0) {
	     fprintf (stderr, "%s: fork: %s\n", prog,
		      strerror(errno));
	     continue;
	 } else if (child == 0) {
	     struct sockaddr_in addr;
	     int addrlen = sizeof(addr);
	     int fd;
	     int one = 1;
	     int port;
	     int xserver;

	     if (getpeername (otherside, (struct sockaddr *)&addr,
			      &addrlen) < 0) {
		 fprintf (stderr, "%s: getpeername: %s\n", prog,
			  strerror(errno));
		 exit (1);
	     }
	     close (otherside);

	     sscanf (tmp, "%d", &port);
	     addr.sin_port = htons(port);
	     fd = socket (AF_INET, SOCK_STREAM, 0);
	     if (fd < 0) {
		 fprintf (stderr, "%s: socket: %s\n", prog, strerror(errno));
		 exit (1);
	     }
#if defined(TCP_NODELAY) && defined(HAVE_SETSOCKOPT)
	     setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (void *)&one,
			 sizeof(one));
#endif
	     if (connect (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		 fprintf (stderr, "%s: connect: %s\n", prog, strerror(errno));
		 exit (1);
	     }
	     xserver = connect_local_xsocket (0);
	     if (xserver < 0)
		 return 1;
	     return start_session (xserver, fd, &key, schedule);
	 } else {
	 }
     }
}

/*
 *
 */

static int
doit_active (char *host, char *user, int debugpp, int tcpp, int port)
{
     des_key_schedule schedule;
     des_cblock key;
     int rendez_vous1 = 0, rendez_vous2 = 0;

     display_num = get_xsockets (&rendez_vous1,
				 tcpp ? &rendez_vous2 : NULL);
     if (display_num < 0)
	 return 1;
     strncpy(xauthfile, tempnam("/tmp", NULL), xauthfile_size);
     if (create_and_write_cookie (xauthfile, cookie, cookie_len))
	 return 1;
     status_output (debugpp);
     for (;;) {
	 fd_set fdset;
	 pid_t child;
	 int fd, thisfd;
	 int zero = 0;
	 int one = 1;

	 FD_ZERO(&fdset);
	 if (rendez_vous1)
	     FD_SET(rendez_vous1, &fdset);
	 if (rendez_vous2)
	     FD_SET(rendez_vous2, &fdset);
	 if (select(FD_SETSIZE, &fdset, NULL, NULL, NULL) <= 0)
	     continue;
	 if (rendez_vous1 && FD_ISSET(rendez_vous1, &fdset))
	     thisfd = rendez_vous1;
	 else if (rendez_vous2 && FD_ISSET(rendez_vous2, &fdset))
	     thisfd = rendez_vous2;
	 else
	     continue;

	 fd = accept (thisfd, NULL, &zero);
	 if (fd < 0)
	     if (errno == EINTR)
		 continue;
	     else {
		 fprintf (stderr, "%s: accept: %s\n", prog,
			  strerror(errno));
		 return 1;
	     }
#if defined(TCP_NODELAY) && defined(HAVE_SETSOCKOPT)
	 setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (void *)&one, sizeof(one));
#endif
	 ++nchild;
	 child = fork ();
	 if (child < 0) {
	     fprintf (stderr, "%s: fork: %s\n", prog,
		      strerror(errno));
	     continue;
	 } else if (child == 0) {
	     int kxd;
	     u_char zero = 0;

	     if (rendez_vous1)
		 close (rendez_vous1);
	     if (rendez_vous2)
		 close (rendez_vous2);
	     kxd = connect_host (host, user, &key, schedule, 0, port);
	     if (kxd < 0)
		 return 1;
	     if (krb_net_write (kxd, &zero, sizeof(zero)) != sizeof(zero)) {
		 fprintf (stderr, "%s: write: %s\n", prog,
			  strerror(errno));
		 return 1;
	     }
	     return copy_encrypted (fd, kxd, &key, schedule);
	 } else {
	     close (fd);
	 }
     }
}

static void
usage(void)
{
    fprintf (stderr, "Usage: %s [-p port] [-d] [-t] [-l remoteuser] host\n",
	     prog);
    exit (1);
}

/*
 * kx - forward x connection over a kerberos-encrypted channel.
 *
 * passive mode if $DISPLAY begins with :
 */

int
main(int argc, char **argv)
{
     int passivep;
     char *disp, *user = NULL;
     int debugp = 0, tcpp = 0;
     int c;
     int port = 0;

     prog = argv[0];
     while((c = getopt(argc, argv, "tdl:p:")) != EOF) {
	 switch(c) {
	 case 'd' :
	     debugp = 1;
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
	  if (p == NULL) {
	       fprintf (stderr, "%s: Who are you?\n", prog);
	       return 1;
	  }
	  user = strdup (p->pw_name);
     }
     if (port == 0)
	 port = k_getportbyname ("kx", "tcp", htons(KX_PORT));
     disp = getenv("DISPLAY");
     passivep = disp != NULL && 
       (*disp == ':' || strncmp(disp, "unix", 4) == 0);
     signal (SIGCHLD, childhandler);
     signal (SIGUSR1, usr1handler);
     signal (SIGUSR2, usr2handler);
     if (passivep)
	 return doit_passive (argv[0], user, debugp, port);
     else
	 return doit_active  (argv[0], user, debugp, tcpp, port);
}
