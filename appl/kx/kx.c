#include "kx.h"

RCSID("$Id$");

char *prog;

static void
usage()
{
     fprintf (stderr, "Usage: %s host\n", prog);
     exit (1);
}

static u_int32_t display_num;
static char xauthfile[MaxPathLen];

/*
 * Establish authenticated connection
 */

static int
connect_host (char *host, des_cblock *key, des_key_schedule schedule,
	      int passivep)
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

     hostent = gethostbyname (host);
     if (hostent == NULL) {
	  fprintf (stderr, "%s: gethostbyname '%s' failed: ", prog, host);
	  return -1;
     }

     memset (&thataddr, 0, sizeof(thataddr));
     thataddr.sin_family = AF_INET;
     thataddr.sin_port   = k_getportbyname ("kx", "tcp", htons(2111));
     memcpy (&thataddr.sin_addr, hostent->h_addr, sizeof(thataddr.sin_addr));

     s = socket (AF_INET, SOCK_STREAM, 0);
     if (s < 0) {
	  fprintf (stderr, "%s: socket failed: %s\n", prog, strerror(errno));
	  return -1;
     }
     if (connect (s, (struct sockaddr *)&thataddr, sizeof(thataddr)) < 0) {
	  fprintf (stderr, "%s: connect(%s) failed: %s\n", prog, host,
		   strerror(errno));
	  return -1;
     }
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
			    &thisaddr, &thataddr, "KXSERV.0");
     if (status != KSUCCESS) {
	  fprintf (stderr, "%s: %s: %s\n", prog, host,
		   krb_get_err_text(status));
	  return -1;
     }
     if (read (s, &b, sizeof(b)) != sizeof(b)) {
	  fprintf (stderr, "%s: read: %s\n", prog,
		   strerror(errno));
	  return -1;
     }
     if (b) {
	  char buf[BUFSIZ];

	  read (s, buf, sizeof(buf));
	  buf[BUFSIZ - 1] = '\0';

	  fprintf (stderr, "%s: %s: %s\n", prog, host, buf);
	  return -1;
     }
     b = passivep;
     if (write (s, &b, sizeof(b)) != sizeof(b)) {
	  fprintf (stderr, "%s: write: %s\n", prog, strerror(errno));
	  return -1;
     }
     if (read (s, &display_num, sizeof(display_num)) !=
	 sizeof(display_num)) {
	  fprintf (stderr, "%s: read: %s\n", prog,
		   strerror(errno));
	  return -1;
     }
     display_num = ntohl(display_num);
     if (read (s, xauthfile, sizeof(xauthfile)) != sizeof(xauthfile)) {
	  fprintf (stderr, "%s: read: %s\n", prog,
		   strerror(errno));
	  return -1;
     }

     memcpy(key, &cred.session, sizeof(des_cblock));
     return s;
}

static int
active (int fd, char *host, des_cblock *iv, des_key_schedule schedule)
{
     int kxd;
     u_char zero = 0;

     kxd = connect_host (host, iv, schedule, 0); /* XXX */
     if (kxd < 0)
	  return 1;
     if (write (kxd, &zero, sizeof(zero)) != sizeof(zero)) {
	  fprintf (stderr, "%s: write: %s\n", prog,
		   strerror(errno));
	  return 1;
     }
     return copy_encrypted (fd, kxd, iv, schedule);
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

     if (read (fd, beg, sizeof(beg)) != sizeof(beg))
	  return 1;
     if (write (xserver, beg, 6) != 6)
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
	  if (write (xserver, len, 6) != 6)
	       return 1;
	  if(write (xserver, auth->name, n) != n)
	       return 1;
	  npad = (4 - (n % 4)) % 4;
	  if (npad) { 
	       if (write (xserver, zeros, npad) != npad)
		    return 1;
	  }
	  if (write (xserver, auth->data, d) != d)
	       return 1;
	  dpad = (4 - (d % 4)) % 4;
	  if (dpad) { 
	       if (write (xserver, zeros, dpad) != dpad)
		    return 1;
	  }
	  XauDisposeAuth(auth);
     } else {
	  if(write(xserver, zeros, 6) != 6)
	       return 1;
     }

     return copy_encrypted (xserver, fd, iv, schedule);
}

static int
passive (int fd, char *host, des_cblock *iv, des_key_schedule schedule)
{
     int xserver;

     xserver = connect_local_xsocket (0);
     if (xserver < 0)
	  return 1;
     return start_session (xserver, fd, iv, schedule);
}

/*
 * Connect to the given host.
 * Iff passivep, give it a port number to call you back and then wait.
 * Else, listen on a local display and then connect to the remote host
 * when a local client gets connected.
 */

static int
doit (char *host, int passivep)
{
     des_key_schedule schedule;
     des_cblock key;
     int rendez_vous;
     int (*fn)(int fd, char *host, des_cblock *iv,
	       des_key_schedule schedule);

     if (passivep) {
	  struct sockaddr_in newaddr;
	  int addrlen;
	  u_char b = passivep;
	  int otherside;
	  pid_t pid;

	  otherside = connect_host (host, &key, schedule, passivep);
	  if (otherside < 0)
	       return 1;

	  rendez_vous = socket (AF_INET, SOCK_STREAM, 0);
	  if (rendez_vous < 0) {
	       fprintf (stderr, "%s: socket failed: %s\n", prog,
			strerror(errno));
	       return 1;
	  }
	  memset (&newaddr, 0, sizeof(newaddr));
	  if (bind (rendez_vous, (struct sockaddr *)&newaddr,
		    sizeof(newaddr)) < 0) {
	       fprintf (stderr, "%s: bind: %s\n", prog, strerror(errno));
	       return 1;
	  }
	  addrlen = sizeof(newaddr);
	  if (getsockname (rendez_vous, (struct sockaddr *)&newaddr,
			   &addrlen) < 0) {
	       fprintf (stderr, "%s: getsockname: %s\n", prog,
			strerror(errno));
	       return 1;
	  }
	  if (listen (rendez_vous, SOMAXCONN) < 0) {
	       fprintf (stderr, "%s: listen: %s\n", prog, strerror(errno));
	       return 1;
	  }
	  if (write (otherside, &newaddr.sin_port, sizeof(newaddr.sin_port))
	      != sizeof(newaddr.sin_port)) {
	       fprintf (stderr, "%s: write: %s\n", prog, strerror(errno));
	       return 1;
	  }
	  close (otherside);
	  fn = passive;
	  pid = fork();
	  if (pid < 0) {
	       fprintf (stderr, "%s: fork: %s\n", prog, strerror(errno));
	       return 1;
	  } else if (pid > 0) {
	       printf ("%d\t%s\n", display_num, xauthfile);
	       exit (0);
	  }
     } else {
	  rendez_vous = get_local_xsocket (1); /* XXX */
	  if (rendez_vous < 0)
	       return 1;
	  fn = active;
     }
     for (;;) {
	  pid_t child;
	  int fd;
	  int zero = 0;

	  fd = accept (rendez_vous, NULL, &zero);
	  if (fd < 0)
	       if (errno == EINTR)
		    continue;
	       else {
		    fprintf (stderr, "%s: accept: %s\n", prog,
			     strerror(errno));
		    return 1;
	       }
	  child = fork ();
	  if (child < 0) {
	       fprintf (stderr, "%s: fork: %s\n", prog,
			strerror(errno));
	       continue;
	  } else if (child == 0) {
	       close (rendez_vous);
	       return (*fn)(fd, host, &key, schedule);
	  } else {
	       close (fd);
	  }
     }
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
     char *disp;

     prog = argv[0];
     if (argc != 2)
	  usage ();
     disp = getenv("DISPLAY");
     passivep = disp != NULL && 
       (*disp == ':' || strncmp(disp, "unix", 4) == 0);
     signal (SIGCHLD, childhandler);
     return doit (argv[1], passivep);
}
