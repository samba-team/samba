#include "kx.h"

RCSID("$Id$");

char *prog;

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

static int
fatal (int fd, char *s)
{
     u_char err = 1;

     write (fd, &err, sizeof(err));
     write (fd, s, strlen(s)+1);
     syslog(LOG_ERR, s);
     return err;
}

static void
cleanup()
{
    if(xauthfile[0])
	unlink(xauthfile);
    if(x_socket[0])
	unlink(x_socket);
}

static int
recv_conn (int sock, des_cblock *key, des_key_schedule schedule,
	   struct sockaddr_in *retaddr)
{
     int status;
     KTEXT_ST ticket;
     AUTH_DAT auth;
     char instance[INST_SZ + 1];
     struct sockaddr_in thisaddr, thataddr;
     int addrlen;
     char version[KRB_SENDAUTH_VLEN];
     char *username;
     u_char ok = 0;
     struct passwd *passwd;

     addrlen = sizeof(thisaddr);
     if (getsockname (sock, (struct sockaddr *)&thisaddr, &addrlen) < 0 ||
	 addrlen != sizeof(thisaddr)) {
	  return 1;
     }
     addrlen = sizeof(thataddr);
     if (getpeername (sock, (struct sockaddr *)&thataddr, &addrlen) < 0 ||
	 addrlen != sizeof(thataddr)) {
	  return 1;
     }

     k_getsockinst (sock, instance);
     status = krb_recvauth (KOPT_DO_MUTUAL, sock, &ticket, "rcmd", instance,
			    &thataddr, &thisaddr, &auth, "", schedule,
			    version);
     if (status != KSUCCESS ||
	 strncmp(version, "KXSERV.0", KRB_SENDAUTH_VLEN) != 0) {
	  return 1;
     }
     passwd = k_getpwnam (auth.pname);
     if (passwd == NULL)
	  return fatal (sock, "Cannot find uid");
     username = strdup (passwd->pw_name);
     if (kuserok(&auth, username) != 0)
	  return fatal (sock, "Permission denied");
     free (username);
     if (setgid (passwd->pw_gid) ||
	 initgroups(passwd->pw_name, passwd->pw_gid) ||
	 setuid(passwd->pw_uid)) {
	  return fatal (sock, "Cannot set uid");
     }
     umask(077);
     if (krb_net_write (sock, &ok, sizeof(ok)) != sizeof(ok))
	  return 1;

     memcpy(key, &auth.session, sizeof(des_cblock));
     *retaddr = thataddr;
     return 0;
}

static int
start_session (int fd, int sock, des_cblock *key,
	       des_key_schedule schedule)
{
     u_char beg[12];
     int bigendianp;
     unsigned n, d, npad, dpad;
     char *protocol_name, *protocol_data;
     u_char zeros[6] = {0, 0, 0, 0, 0, 0};

     if (krb_net_read (fd, beg, sizeof(beg)) != sizeof(beg))
	  return 1;
     if (krb_net_write (sock, beg, 6) != 6)
	  return 1;
     bigendianp = beg[0] == 'B';
     if (bigendianp) {
	  n = (beg[6] << 8) | beg[7];
	  d = (beg[8] << 8) | beg[9];
     } else {
	  n = (beg[7] << 8) | beg[6];
	  d = (beg[9] << 8) | beg[8];
     }
     npad = (4 - (n % 4)) % 4;
     dpad = (4 - (d % 4)) % 4;
     protocol_name = malloc(n + npad);
     protocol_data = malloc(d + dpad);
     if (krb_net_read (fd, protocol_name, n + npad) != n + npad)
	  return 1;
     if (krb_net_read (fd, protocol_data, d + dpad) != d + dpad)
	  return 1;
     if (strncmp (protocol_name, COOKIE_TYPE, strlen(COOKIE_TYPE)) != 0)
	  return 1;
     if (d != cookie_len ||
	 memcmp (protocol_data, cookie, cookie_len) != 0)
	  return 1;
     if (krb_net_write (sock, zeros, 6) != 6)
	  return 1;
     return copy_encrypted (fd, sock, key, schedule);
}

static int
doit_conn (int fd, struct sockaddr_in *thataddr,
	   des_cblock *key, des_key_schedule schedule)
{
  int sock;
  int one = 1;

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    char msg[200];
    sprintf (msg, "socket: %s", strerror(errno));
    return fatal (sock, msg);
  }
#ifdef TCP_NODELAY
  setsockopt (sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
  if (connect (sock, (struct sockaddr *)thataddr,
	       sizeof(*thataddr)) < 0) {
    abort ();
  }
  return start_session (fd, sock, key, schedule);
}

/*
 *
 */

static int
check_user_console ()
{
     struct stat sb;

     if (stat ("/dev/console", &sb) < 0)
	  return fatal (0, "Cannot stat /dev/console");
     if (getuid() != sb.st_uid)
	  return fatal (0, "Permission denied");
     return 0;
}

static int
doit(int sock, int tcpp)
{
     u_char passivep;
     struct sockaddr_in thataddr;
     des_key_schedule schedule;
     des_cblock key;
     int localx, tcpx;
     u_int32_t tmp;

     if (recv_conn (sock, &key, schedule, &thataddr))
	  return 1;
     if (krb_net_read (sock, &passivep, sizeof(passivep)) != sizeof(passivep))
	  return 1;
     if (passivep) {
	  char tmp[16];

	  display_num = get_xsockets (&localx, tcpp ? &tcpx : NULL);
	  if (display_num < 0)
	       return 1;
	  sprintf (tmp, "%u", display_num);
	  if (krb_net_write (sock, tmp, sizeof(tmp)) != sizeof(tmp))
	       return 1;
	  strncpy(xauthfile, tempnam("/tmp", NULL), xauthfile_size);
	  if (krb_net_write (sock, xauthfile, xauthfile_size) !=
	      xauthfile_size)
	       return 1;
	  if(create_and_write_cookie (xauthfile, cookie, cookie_len))
	       return 1;
	  {
	      char tmp[6];

	      if(krb_net_read(sock, tmp, sizeof(tmp)) != sizeof(tmp))
		  return -1;
	      thataddr.sin_port = htons(atoi(tmp));
	  }

	  for (;;) {
	       pid_t child;
	       int fd;
	       int zero = 0;
	       int one = 1;
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
			 char msg[200];
			 sprintf (msg, "accept: %s\n", strerror (errno));
			 return fatal (sock, msg);
		    }
#ifdef TCP_NODELAY
	       setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
	       child = fork ();
	       if (child < 0) {
		    char msg[200];
		    sprintf (msg, "fork: %s\n", strerror (errno));
		    return fatal(sock, msg);
	       } else if (child == 0) {
		    close (localx);
		    if (tcpp)
			 close (tcpx);
		    return doit_conn (fd, &thataddr, &key, schedule);
	       } else {
		    close (fd);
	       }
	  }
     } else {
	  if (check_user_console ())
	       return 1;

	  localx = connect_local_xsocket (0);
	  if (localx < 0)
	       return 1;
	  return copy_encrypted (localx, sock, &key, schedule);
     }
}

static void
usage ()
{
     fprintf (stderr, "Usage: %s [-i] [-t]\n", prog);
     exit (1);
}

/*
 * xkd - receive a forwarded X conncection
 */

int
main (int argc, char **argv)
{
     int c;
     int no_inetd = 0;
     int tcpp = 0;

     prog = argv[0];

     while( (c = getopt (argc, argv, "it")) != EOF) {
	  switch (c) {
	  case 'i':
	       no_inetd = 1;
	       break;
	  case 't':
	       tcpp = 1;
	       break;
	  case '?':
	  default:
	       usage ();
	  }
     }

     if (no_inetd)
	  mini_inetd (k_getportbyname("kx", "tcp", htons(KX_PORT)));
     openlog(prog, LOG_PID|LOG_CONS, LOG_DAEMON);
     signal (SIGCHLD, childhandler);
     return doit(STDIN_FILENO, tcpp);
}
