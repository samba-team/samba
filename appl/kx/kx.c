#include "kx.h"

RCSID("$Id$");

static char *prog;

static void
usage()
{
  fprintf (stderr, "Usage: %s local-display-number host|display\n",
	   prog);
  exit (1);
}

static int
doit_host (char *host, unsigned dnr, int fd)
{
  CREDENTIALS cred;
  KTEXT_ST text;
  MSG_DAT msg;
  int status;
  des_key_schedule schedule;
  struct sockaddr_in thisaddr, thataddr;
  int addrlen;
  void *ret;
  struct hostent *hostent;
  int s;
  struct sockaddr_un unixaddr;
  des_cblock iv1, iv2;
  int num1 = 0, num2 = 0;

  /*
   * Establish authenticated connection
   */

  hostent = gethostbyname (host);
  if (hostent == NULL) {
    fprintf (stderr, "%s: gethostbyname '%s' failed: ", prog, host);
    return 1;
  }

  memset (&thataddr, 0, sizeof(thataddr));
  thataddr.sin_family = AF_INET;
  thataddr.sin_port   = k_getportbyname ("kx", "tcp", htons(2111));
  memcpy (&thataddr.sin_addr, hostent->h_addr, sizeof(thataddr.sin_addr));

  s = socket (AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    fprintf (stderr, "%s: socket failed: %s\n", prog, k_strerror(errno));
    return 1;
  }
  if (connect (s, (struct sockaddr *)&thataddr, sizeof(thataddr)) < 0) {
    fprintf (stderr, "%s: connect(%s) failed: %s\n", prog, host,
	     k_strerror(errno));
    return 1;
  }
  addrlen = sizeof(thisaddr);
  if (getsockname (s, (struct sockaddr *)&thisaddr, &addrlen) < 0 ||
      addrlen != sizeof(thisaddr)) {
    fprintf (stderr, "%s: getsockname(%s) failed: %s\n",
	     prog, host, k_strerror(errno));
    return 1;
  }
  status = krb_sendauth (KOPT_DO_MUTUAL, s, &text, "rcmd",
			 host, krb_realmofhost (host),
			 getpid(), &msg, &cred, schedule,
			 &thisaddr, &thataddr, "KXSERV.0");
  if (status != KSUCCESS) {
    fprintf (stderr, "%s: %s: %s\n", prog, host,
	     krb_get_err_text(status));
    return 1;
  }
  /*
   * Send parameters.
   */

  {
    u_char b = dnr;
    char buf[128];
    int ret;
    
    if (write (s, &b, sizeof(b)) != sizeof(b)) {
      fprintf (stderr, "%s: write: %s\n", prog, k_strerror (errno));
      return 1;
    }
    if (read (s, &b, sizeof(b)) != sizeof(b)) {
      fprintf (stderr, "%s: read: %s\n", prog, k_strerror (errno));
      return 1;
    }
    if (b) {
      fprintf (stderr, "%s: Error from '%s': ", prog, host);
      ret = read (s, buf, sizeof(buf));
      if(ret < 0) {
	fprintf (stderr, "%s: read: %s\n", prog, k_strerror (errno));
	return 1;
      }
      fprintf (stderr, "%s\n", buf);
      return 1;
    }
  }

  memcpy (&iv1, &cred.session, sizeof(iv1));
  memcpy (&iv2, &cred.session, sizeof(iv2));
  for (;;) {
    fd_set fdset;
    int ret;
    char buf[BUFSIZ];

    FD_ZERO(&fdset);
    FD_SET(s, &fdset);
    FD_SET(fd, &fdset);

    ret = select (256, &fdset, NULL, NULL, NULL); /* XXX */
    if (ret < 0 && errno != EINTR) {
      fprintf (stderr, "%s: select: %s\n", prog, k_strerror (errno));
      return 1;
    }
    if (FD_ISSET(s, &fdset)) {
      ret = read (s, buf, sizeof(buf));
      if (ret == 0)
	return 0;
      if (ret < 0) {
	fprintf (stderr, "%s: read: %s\n", prog, k_strerror (errno));
	return 1;
      }
#ifndef NOENCRYPTION
      des_cfb64_encrypt (buf, buf, ret, schedule, &iv1,
			 &num1, DES_DECRYPT);
#endif
      ret = krb_net_write (fd, buf, ret);
      if (ret < 0) {
	fprintf (stderr, "%s: write: %s\n", prog, k_strerror (errno));
	return 1;
      }
    }
    if (FD_ISSET(fd, &fdset)) {
      ret = read (fd, buf, sizeof(buf));
      if (ret == 0)
	return 0;
      if (ret < 0) {
	fprintf (stderr, "%s: read: %s\n", prog, k_strerror (errno));
	return 1;
      }
#ifndef NOENCRYPTION
      des_cfb64_encrypt (buf, buf, ret, schedule, &iv2,
			 &num2, DES_ENCRYPT);
#endif
      ret = krb_net_write (s, buf, ret);
      if (ret < 0) {
	fprintf (stderr, "%s: write: %s\n", prog, k_strerror (errno));
	return 1;
      }
    }
  }
}

/*
 * Listen for calls to the remote X-server.
 */

static int
doit (unsigned localnr, char *host, unsigned remotenr)
{
  int fd;
  struct sockaddr_un addr;
  int dnr;

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf (stderr, "%s: socket failed: %s\n", prog, k_strerror(errno));
    return 1;
  }    
  addr.sun_family = AF_UNIX;
  sprintf (addr.sun_path, "/tmp/.X11-unix/X%u", localnr);
  unlink (addr.sun_path);
  if(bind (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf (stderr, "%s: bind failed: %s\n", prog,
	     k_strerror(errno));
    return 1;
  }
  if (listen (fd, 5) < 0) {
    fprintf (stderr, "%s: listen failed: %s\n", prog,
	     k_strerror(errno));
    return 1;
  }
  for (;;) {
    int newfd;
    struct sockaddr_un that;
    int len;
    pid_t pid;

    len = sizeof (that);
    newfd = accept (fd, (struct sockaddr *)&that, &len);
    if (newfd < 0)
      if (errno == EINTR)
	continue;
      else {
	fprintf (stderr, "%s: accept: %s\n", prog, k_strerror (errno));
	return 1;
      }
    fprintf (stderr, "%s: New connection\n", prog);
    pid = fork ();
    if (pid < 0) {
      fprintf (stderr, "%s: fork: %s\n", prog, k_strerror (errno));
      return 1;
    } else if (pid == 0) {
      close (fd);
      return doit_host (host, remotenr, newfd);
    } else {
      close (newfd);
    }
  }
}

static
RETSIGTYPE
childhandler ()
{
  pid_t pid;
  int status;

  do { 
    pid = waitpid (-1, &status, WNOHANG|WUNTRACED);
  } while(pid > 0);
  signal (SIGCHLD, childhandler);
}

/*
 * fx - forward x connection.
 */

int
main(argc, argv)
     int argc;
     char **argv;
{
  int dnr;
  char *p;

  prog = argv[0];
  if (argc != 3)
    usage ();

  p = strchr (argv[2], ':');
  if (p) {
    *p = '\0';
    dnr = atoi (p+1);
  } else
    dnr = 0;

  signal (SIGCHLD, childhandler);

  return doit (atoi(argv[1]), argv[2], dnr);
}
