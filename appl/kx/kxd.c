#include "kx.h"

RCSID("$Id$");

char *prog;

static int
fatal (int fd, char *s)
{
     u_char err = 1;

     write (fd, &err, sizeof(err));
     write (fd, s, strlen(s)+1);
     syslog(LOG_ERR, s);
     return err;
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
     if (write (sock, &ok, sizeof(ok)) != sizeof(ok))
	  return 1;

     memcpy(key, &auth.session, sizeof(des_cblock));
     *retaddr = thataddr;
     return 0;
}

static int
doit_conn (int fd, struct sockaddr_in *thataddr,
	   des_cblock *key, des_key_schedule schedule)
{
  int sock;

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    char msg[200];
    sprintf (msg, "socket: %s", strerror(errno));
    return fatal (sock, msg);
  }
  if (connect (sock, (struct sockaddr *)thataddr,
	       sizeof(*thataddr)) < 0) {
    abort ();
  }
  return copy_encrypted (fd, sock, key, schedule);
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
doit(int sock)
{
     u_char passivep;
     struct sockaddr_in thataddr;
     des_key_schedule schedule;
     des_cblock key;
     int localx;

     if (recv_conn (sock, &key, schedule, &thataddr))
	  return 1;
     if (read (sock, &passivep, sizeof(passivep)) != sizeof(passivep))
	  return 1;
     if (passivep) {
	  if (read (sock, &thataddr.sin_port, sizeof(thataddr.sin_port))
	      != sizeof(thataddr.sin_port))
	       return 1;
	  localx = get_local_xsocket (1);
	  if (localx < 0)
	       return 1;
	  for (;;) {
	       pid_t child;
	       int fd;
	       int zero = 0;

	       fd = accept (localx, NULL, &zero);
	       if (fd < 0)
		    if (errno == EINTR)
			 continue;
		    else {
			 char msg[200];
			 sprintf (msg, "accept: %s\n", strerror (errno));
			 return fatal (sock, msg);
		    }
	       child = fork ();
	       if (child < 0) {
		    char msg[200];
		    sprintf (msg, "fork: %s\n", strerror (errno));
		    return fatal(sock, msg);
	       } else if (child == 0) {
		    close (localx);
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

/*
 * xkd - receive a forwarded X conncection
 */

int
main (int argc, char **argv)
{
     prog = argv[0];

     openlog(prog, LOG_PID|LOG_CONS, LOG_DAEMON);
     signal (SIGCHLD, childhandler);
     return doit(0);
}
