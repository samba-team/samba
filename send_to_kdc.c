#include "krb5_locl.h"

static int
send_and_recv (int fd,
	       struct sockaddr_in *addr,
	       krb5_data *send,
	       krb5_data *recv)
{
     struct fdset fdset;
     struct timeval timeout;
     int ret;
     long nbytes;

     if (sendto (fd, send->data, send->len, 0,
		 (struct sockaddr *)addr, sizeof(*addr)) < 0)
	  return -1;
     FD_ZERO(&fdset);
     FD_SET(fd, &fdset);
     timeout.tv_sec  = 3;
     timeout.tv_usec = 0;
     ret = select (fd + 1, &fdset, NULL, NULL, &timeout);
     if (ret <= 0)
	  return -1;
     else {
	  ioctl (fd, FIONREAD, &nbytes);

	  nbytes -= sizeof(struct udphdr) + sizeof(struct iphdr);

	  recv->data = malloc (nbytes);
	  ret = recvfrom (fd, recv->data, nbytes, 0, NULL, 0);
	  if (ret < 0) {
	       free (recv->data);
	       return -1;
	  }
	  recv->data = realloc (recv->data, ret);
	  recv->len  = ret;
	  return 0;
     }
}

krb5_error_code
krb5_sentdo_kdc (krb5_context context,
		 const krb5_data *send,
		 const krb5_data *realm,
		 krb5_data *receive)
{
     krb5_error_code err;
     char **hostlist, **hp, *p;
     struct hostent *hostent;
     int fd;
     int port;
     int i;

     port = krb5_getportbyname ("kerberos", "udp", htons(750));
     fd = socket (AF_INET, SOCK_DGRAM, 0);
     if (fd < 0)
	  return errno;

     err = krb5_get_krbhst (context, realm, &hostlist);
     if (err) {
	  close (fd);
	  return err;
     }
     for (i = 0; i < 3; ++i)
	  for (hp = hostlist; p = *hp; ++hp) {
	       char *addr;

	       hostent = gethostbyname (p);
	       while (addr = *hostent->h_addr_list++) {
		    struct sockaddr_in a;
		    
		    memset (a, 0, sizeof(a));
		    a.sin_family = AF_INET;
		    a.sin_port   = port;
		    a.sin_addr   = *((struct in_addr *)addr);
		    
		    if (send_and_recv (fd, &a, send, recv) == 0) {
			 krb5_free_krbhst (context, hostlist);
			 return KDC_ERR_NONE;
		    }
	       }
	  }
     krb5_free_krbhst (context, hostlist);
     return KRB5_KDC_UNREACH;
}
