#include "kx.h"

RCSID("$Id$");

static int
fatal (int fd, char *s)
{
     u_char err = 1;

     write (fd, &err, sizeof(err));
     write (fd, s, strlen(s)+1);
     return err;
}

static int
doit(int sock)
{
     int status;
     KTEXT_ST ticket;
     AUTH_DAT auth;
     char instance[INST_SZ + 1];
     des_key_schedule schedule;
     struct sockaddr_in thisaddr, thataddr;
     int addrlen;
     int len;
     char buf[BUFSIZ];
     void *data;
     struct passwd *passwd;
     char version[KRB_SENDAUTH_VLEN];
     int fd;
     struct stat sb;
     struct sockaddr_un addr;
     char *username;
     des_cblock iv1, iv2;
     int num1 = 0, num2 = 0;
     unsigned dnr;

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
     {
	  u_char b;

	  if (read (sock, &b, sizeof(b)) != sizeof(b))
	       return 1;
	  dnr = b;
     }

     if (stat ("/dev/console", &sb) < 0)
	  return fatal (fd, "Cannot stat /dev/console");
     passwd = getpwuid (sb.st_uid);
     if (passwd == NULL)
	  return fatal (fd, "Cannot find uid");
     username = strdup (passwd->pw_name);
     if (kuserok(&auth, username) != 0)
	  return fatal (fd, "Permission denied");
     free (username);
     if (setgid (passwd->pw_gid) ||
	 initgroups(passwd->pw_name, passwd->pw_gid) ||
	 setuid(passwd->pw_uid)) {
	  return fatal (fd, "Cannot set uid");
     }
     fd = socket (AF_UNIX, SOCK_STREAM, 0);
     if (fd < 0)
	  return fatal (fd, "Cannot create socket");
     addr.sun_family = AF_UNIX;
     sprintf (addr.sun_path, "/tmp/.X11-unix/X%u", dnr);
     if (connect (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	  return fatal (fd, "Cannot connect");
     memcpy (&iv1, &auth.session, sizeof(iv1));
     memcpy (&iv2, &auth.session, sizeof(iv2));
     {
	  u_char b = 0;

	  if (write (sock, &b, sizeof(b)) != sizeof(b))
	      return 1;
     }
     for (;;) {
	  fd_set fdset;
	  int ret;
	  char buf[BUFSIZ];

	  FD_ZERO(&fdset);
	  FD_SET(sock, &fdset);
	  FD_SET(fd, &fdset);

	  ret = select (fd+1, &fdset, NULL, NULL, NULL);
	  if (ret < 0 && errno != EINTR)
	       return 1;
	  if (FD_ISSET(sock, &fdset)) {
 	       ret = read (sock, buf, sizeof(buf));
	       if (ret == 0)
		    return 0;
	       if (ret < 0)
		    return 1;
#ifndef NOENCRYPTION
	       des_cfb64_encrypt (buf, buf, ret, schedule,
				&iv1, &num1, DES_DECRYPT);
#endif
	       ret = krb_net_write (fd, buf, ret);
	       if (ret < 0)
		    return 1;
	  }
	  if (FD_ISSET(fd, &fdset)) {
	       ret = read (fd, buf, sizeof(buf));
	       if (ret == 0)
		    return 0;
	       if (ret < 0)
		    return 1;
#ifndef NOENCRYPTION
	       des_cfb64_encrypt (buf, buf, ret, schedule,
				&iv2, &num2, DES_ENCRYPT);
#endif
	       ret = krb_net_write (STDOUT_FILENO, buf, ret);
	       if (ret < 0)
		    return 1;
	  }
     }
}

/*
 * xkd - receive a forwarded X conncection
 */

int
main (int argc, char **argv)
{
     return doit(0);
}
