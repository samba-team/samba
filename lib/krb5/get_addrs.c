/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
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
 *      This product includes software developed by Kungliga Tekniska 
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

#include "krb5_locl.h"

RCSID("$Id$");

#if defined(HAVE_SYS_IOCTL_H) && SunOS != 4
#include <sys/ioctl.h>
#endif
#ifdef __osf__
/* hate */
struct rtentry;
struct mbuf;
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */

static krb5_error_code
gethostname_fallback (krb5_addresses *res)
{
     krb5_error_code err;
     char hostname[MAXHOSTNAMELEN];
     struct hostent *hostent;

     if (gethostname (hostname, sizeof(hostname)))
	  return errno;
     hostent = gethostbyname (hostname);
     if (hostent == NULL)
	  return errno;
     res->len = 1;
     res->val = malloc (sizeof(*res->val));
     if (res->val == NULL)
	 return ENOMEM;
     res->val[0].addr_type = hostent->h_addrtype;
     res->val[0].address.data = NULL;
     res->val[0].address.length = 0;
     err = krb5_data_copy (&res->val[0].address,
			   hostent->h_addr,
			   hostent->h_length);
     if (err) {
	 free (res->val);
	 return err;
     }
     return 0;
}

/*
 *
 * Try to figure out the addresses of all configured interfaces with a
 * lot of magic ioctls.
 * Include loopback (lo*) interfaces iff loop.
 */

#if defined(SIOCGIFCONF) && defined(SIOCGIFFLAGS) && defined(SIOCGIFADDR)
static krb5_error_code
find_all_addresses (krb5_addresses *res, int loop)
{
     krb5_error_code err;
     int fd;
     char buf[BUFSIZ];
     struct ifreq ifreq;
     struct ifconf ifconf;
     int num, j;
     char *p;
     size_t sz;

     fd = socket(AF_INET, SOCK_DGRAM, 0);
     if (fd < 0)
	  return -1;

     ifconf.ifc_len = sizeof(buf);
     ifconf.ifc_buf = buf;
     if(ioctl(fd, SIOCGIFCONF, &ifconf) < 0)
	  return -1;
     num = ifconf.ifc_len / sizeof(struct ifreq);
     res->len = num;
     res->val = calloc(num, sizeof(*res->val));
     if (res->val == NULL) {
	 close (fd);
	 return ENOMEM;
     }

     j = 0;
     ifreq.ifr_name[0] = '\0';
     for (p = ifconf.ifc_buf;
	  p < ifconf.ifc_buf + ifconf.ifc_len;
	  p += sz) {
          struct ifreq *ifr = (struct ifreq *)p;

	  /* This is somewhat kludgy, but it seems to work. */

	  sz = sizeof(*ifr);
#ifdef SOCKADDR_HAS_SA_LEN
	  if(ifr->ifr_addr.sa_len)
	      sz = sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;
#endif
	  if(strncmp(ifreq.ifr_name,
		     ifr->ifr_name,
		     sizeof(ifr->ifr_name)) == 0)
	      continue;

	  if(ioctl(fd, SIOCGIFFLAGS, ifr) < 0) {
	      close (fd);
	      free (res->val);
	      return errno;
	  }

	  if(!(ifr->ifr_flags & IFF_UP)
	     || (loop == 0 && (ifr->ifr_flags & IFF_LOOPBACK)))
	      continue;

	  /*
	   * Get the address of the interface.  If this fails, it's
	   * usually because this interface is up, but has no address
	   * configured.  There might be some fatal errors for which
	   * we should bail out, but now we prefer ignoring them.
	   */
	  if(ioctl(fd, SIOCGIFADDR, ifr) < 0)
	      continue;

	  switch (ifr->ifr_addr.sa_family) {
#ifdef AF_INET
	  case AF_INET: {
	      unsigned char addr[4];
	      struct sockaddr_in *sin;
	      res->val[j].addr_type = AF_INET;
	      /* This is somewhat XXX */
	      sin = (struct sockaddr_in*)&ifr->ifr_addr;
	      memcpy(addr, &sin->sin_addr, 4);
	      err = krb5_data_copy(&res->val[j].address,
				   addr, 4);
	      if (err) {
		  close (fd);
		  free (res->val);
		  return ENOMEM;
	      }
	      ++j;
	      break;
	  }
#endif /* AF_INET */

/*
 * This is not an correct nor ideal test.
 */

#if defined(AF_INET6) && defined(HAVE_NETINET_IN6_H)
	  case AF_INET6: {
	      res->val[j].addr_type = AF_INET6;
	      err = krb5_data_copy(&res->val[j].address,
				   &ifr->ifr_addr,
				   sizeof(struct sockaddr_in6));
	      if (err) {
		  close (fd);
		  free (res->val);
		  return ENOMEM;
	      }
	      ++j;
	      break;
	  }
#endif /* AF_INET6 */
	  default:
	      break;
	  }
	  ifreq = *ifr;
     }
     close (fd);
     if (j != num) {
	 void *tmp;

	 res->len = j;
	 tmp = realloc (res->val, j * sizeof(*res->val));
	 if (tmp == NULL) {
	     free (res->val);
	     return ENOMEM;
	 }
	 res->val = tmp;
     }
     return 0;
}
#endif /* SIOCGIFCONF */

/*
 * Try to get all addresses, but return the one corresponding to
 * `hostname' if we fail.
 *
 * Don't include any loopback addresses (interfaces of name lo*).
 *
 */

krb5_error_code
krb5_get_all_client_addrs (krb5_addresses *res)
{
#if !defined(SIOCGIFCONF) || !defined(SIOCGIFFLAGS) || !defined(SIOCGIFADDR)
    return gethostname_fallback (res);
#else
    return find_all_addresses (res, 0);
#endif /* SIOCGIFCONF */
}

/*
 * XXX
 */

#if 0
krb5_error_code
krb5_get_all_server_addrs ()
{
    return 0;
}
#endif
