#include "kx.h"

RCSID("$Id$");

static int
do_enccopy (int fd1, int fd2, int mode, des_cblock *iv,
	    des_key_schedule schedule, int *num)
{
     int ret;
     u_char buf[BUFSIZ];

     ret = read (fd1, buf, sizeof(buf));
     if (ret == 0)
	  return 0;
     if (ret < 0) {
	  fprintf (stderr, "%s: read: %s\n", prog, strerror (errno));
	  return ret;
     }
#ifndef NOENCRYPTION
     des_cfb64_encrypt (buf, buf, ret, schedule, iv,
			num, mode);
#endif
     ret = krb_net_write (fd2, buf, ret);
     if (ret < 0) {
	  fprintf (stderr, "%s: write: %s\n", prog, strerror (errno));
	  return ret;
     }
     return 1;
}

/*
 * Copy data from `fd1' to `fd2', encrypting it.  Data in the other
 * direction is of course, decrypted.
 */

int
copy_encrypted (int fd1, int fd2, des_cblock *iv,
		des_key_schedule schedule)
{
     des_cblock iv1, iv2;
     int num1 = 0, num2 = 0;

     memcpy (&iv1, iv, sizeof(iv1));
     memcpy (&iv2, iv, sizeof(iv2));
     for (;;) {
	  fd_set fdset;
	  int ret;

	  FD_ZERO(&fdset);
	  FD_SET(fd1, &fdset);
	  FD_SET(fd2, &fdset);

	  ret = select (max(fd1, fd2)+1, &fdset, NULL, NULL, NULL);
	  if (ret < 0 && errno != EINTR) {
	       fprintf (stderr, "%s: select: %s\n", prog, strerror (errno));
	       return 1;
	  }
	  if (FD_ISSET(fd1, &fdset)) {
	       ret = do_enccopy (fd1, fd2, DES_ENCRYPT, &iv1, schedule, &num1);
	       if (ret <= 0)
		    return ret;
	  }
	  if (FD_ISSET(fd2, &fdset)) {
	       ret = do_enccopy (fd2, fd1, DES_DECRYPT, &iv2, schedule, &num2);
	       if (ret <= 0)
		    return ret;
	  }
     }
}

/*
 * Signal handler that justs waits for the children when they die.
 */

RETSIGTYPE
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

/*
 * Allocate and listen on a local X server socket.
 */

#define TMPX11 "/tmp/.X11-unix"

char x_socket[MaxPathLen];

int
get_local_xsocket (int *num)
{
     int fd;
     struct sockaddr_un addr;
     int dpy;
     int oldmask;

     oldmask = umask(0);
     mkdir (TMPX11, 01777);
     umask (oldmask);

     fd = socket (AF_UNIX, SOCK_STREAM, 0);
     if (fd < 0) {
	  fprintf (stderr, "%s: socket: %s\n", prog, strerror(errno));
	  return fd;
     }    
     addr.sun_family = AF_UNIX;
     for(dpy = 4; dpy < 256; ++dpy) {
	  struct stat statbuf;

	  sprintf (addr.sun_path, TMPX11 "/X%u", dpy);
	  if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	       if (errno == EADDRINUSE)
		    continue;
	       else
		    return -1;
	  else
	       break;
     }
     if (dpy == 256) {
	  fprintf (stderr, "%s: no free x-servers\n", prog);
	  return -1;
     }
     if (listen (fd, SOMAXCONN) < 0) {
	  fprintf (stderr, "%s: listen: %s\n", prog,
		   strerror(errno));
	  return -1;
     }
     strcpy(x_socket, addr.sun_path);
     *num = dpy;
     return fd;
}

/*
 *
 */

int
connect_local_xsocket (unsigned dnr)
{
     int fd;
     struct sockaddr_un addr;

     fd = socket (AF_UNIX, SOCK_STREAM, 0);
     if (fd < 0) {
	  fprintf (stderr, "%s: socket: %s\n", prog, strerror(errno));
	  return fd;
     }    
     addr.sun_family = AF_UNIX;
     sprintf (addr.sun_path, "/tmp/.X11-unix/X%u", dnr);
     if (connect (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	  fprintf (stderr, "%s: connect: %s\n", prog,
		   strerror(errno));
	  return -1;
     }
     return fd;
}
