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

#ifndef X_UNIX_PATH
#define X_UNIX_PATH "/tmp/.X11-unix/X"
#endif

char x_socket[MaxPathLen];

/*
 * Allocate and listen on a local X server socket and a TCP socket.
 * Return the display number.
 */

int
get_xsockets (int *unix_socket, int *tcp_socket)
{
     int unixfd, tcpfd;
     struct sockaddr_un unixaddr;
     struct sockaddr_in tcpaddr;
     int dpy;
     int oldmask;
     struct hostent *h;
     struct in_addr local;
     char *dir, *p;

     dir = strdup (X_UNIX_PATH);
     p = strrchr (dir, '/');
     if (p)
       *p = '\0';

     oldmask = umask(0);
     mkdir (dir, 01777);
     umask (oldmask);
     free (dir);

     h = gethostbyname ("localhost");
     if (h)
	 memcpy (&local, h->h_addr, h->h_length);
     else
	 local.s_addr = inet_addr ("127.0.0.1");

     for(dpy = 4; dpy < 256; ++dpy) {
	 unixfd = socket (AF_UNIX, SOCK_STREAM, 0);
	 if (unixfd < 0) {
	     fprintf (stderr, "%s: socket: %s\n", prog, strerror(errno));
	     return -1;
	 }    
	 memset (&unixaddr, 0, sizeof(unixaddr));
	 unixaddr.sun_family = AF_UNIX;
	 sprintf (unixaddr.sun_path, X_UNIX_PATH "%u", dpy);
	 if(bind(unixfd,
		 (struct sockaddr *)&unixaddr,
		 sizeof(unixaddr)) < 0) {
	     close (unixfd);
	     if (errno == EADDRINUSE ||
		 errno == EACCES) /* Cray return EACCESS */
		 continue;
	     else
		 return -1;
	 }

	 if (tcp_socket) {
	     tcpfd = socket (AF_INET, SOCK_STREAM, 0);
	     if (tcpfd < 0) {
		 fprintf (stderr, "%s: socket: %s\n", prog,
			  strerror(errno));
		 close (unixfd);
		 return -1;
	     }
	     memset (&tcpaddr, 0, sizeof(tcpaddr));
	     tcpaddr.sin_family = AF_INET;
	     tcpaddr.sin_addr = local;
	     tcpaddr.sin_port = htons(6000 + dpy);
	     if (bind (tcpfd, (struct sockaddr *)&tcpaddr,
		       sizeof(tcpaddr)) < 0) {
		 close (unixfd);
		 close (tcpfd);
		 if (errno == EADDRINUSE)
		     continue;
		 else
		     return -1;
	     }
	 }
	 break;
     }
     if (dpy == 256) {
	  fprintf (stderr, "%s: no free x-servers\n", prog);
	  return -1;
     }
     if (listen (unixfd, SOMAXCONN) < 0) {
	  fprintf (stderr, "%s: listen: %s\n", prog,
		   strerror(errno));
	  return -1;
     }
     if (tcp_socket)
	 if (listen (tcpfd, SOMAXCONN) < 0) {
	     fprintf (stderr, "%s: listen: %s\n", prog,
		      strerror(errno));
	     return -1;
	 }
     strcpy(x_socket, unixaddr.sun_path);
     *unix_socket = unixfd;
     if (tcp_socket)
	 *tcp_socket = tcpfd;
     return dpy;
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
