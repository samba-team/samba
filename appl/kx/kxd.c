#include "kx.h"

RCSID("$Id$");

char *prog;

static u_int32_t display_num;
static char xauthfile[MaxPathLen];
static u_char cookie[32];
static size_t cookie_len;

#define COOKIE_TYPE "MIT-MAGIC-COOKIE-1"

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
     umask(077);
     if (write (sock, &ok, sizeof(ok)) != sizeof(ok))
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

     if (read (fd, beg, sizeof(beg)) != sizeof(beg))
	  return 1;
     if (write (sock, beg, 6) != 6)
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
     if (read (fd, protocol_name, n + npad) != n + npad)
	  return 1;
     if (read (fd, protocol_data, d + dpad) != d + dpad)
	  return 1;
     if (strncmp (protocol_name, COOKIE_TYPE, strlen(COOKIE_TYPE)) != 0)
	  return 1;
     if (d != cookie_len ||
	 memcmp (protocol_data, cookie, cookie_len) != 0)
	  return 1;
     if (write (sock, zeros, 6) != 6)
	  return 1;
     return copy_encrypted (fd, sock, key, schedule);
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
create_and_write_cookie (char *xauthfile,
			 u_char *cookie,
			 size_t sz)
{
     Xauth auth;
     char tmp[64];
     FILE *f;
     char hostname[MaxHostNameLen];

     auth.family = FamilyLocal;
     k_gethostname (hostname, sizeof(hostname));
     auth.address = hostname;
     auth.address_length = strlen(auth.address);
     sprintf (tmp, "%d", display_num);
     auth.number_length = strlen(tmp);
     auth.number = tmp;
     auth.name = COOKIE_TYPE;
     auth.name_length = strlen(auth.name);
     auth.data_length = sz;
     auth.data = (char*)cookie;
     des_rand_data (cookie, sz);
     cookie_len = sz;

     f = fopen(xauthfile, "w");
     if(XauWriteAuth(f, &auth) == 0) {
	  fclose(f);
	  return 1;
     }
     if(fclose(f))
	  return 1;
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
     u_int32_t tmp;

     if (recv_conn (sock, &key, schedule, &thataddr))
	  return 1;
     if (read (sock, &passivep, sizeof(passivep)) != sizeof(passivep))
	  return 1;
     if (passivep) {
	  localx = get_local_xsocket (&display_num);
	  if (localx < 0)
	       return 1;
	  tmp = htonl(display_num);
	  if (write (sock, &tmp, sizeof(tmp)) != sizeof(tmp))
	       return 1;
	  strncpy(xauthfile, tempnam("/tmp", NULL), sizeof(xauthfile));
	  if (write (sock, xauthfile, sizeof(xauthfile)) !=
	      sizeof(xauthfile))
	       return 1;
	  if(create_and_write_cookie (xauthfile, cookie,
				      sizeof(cookie)))
	       return 1;
	  if (read (sock, &thataddr.sin_port, sizeof(thataddr.sin_port))
	      != sizeof(thataddr.sin_port))
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
