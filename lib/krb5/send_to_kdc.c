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

static int
send_and_recv (int fd,
	       time_t tmout,
	       struct sockaddr_in *addr,
	       const krb5_data *send,
	       krb5_data *recv)
{
     struct fd_set fdset;
     struct timeval timeout;
     int ret;
     int nbytes;

     if (sendto (fd, send->data, send->length, 0,
		 (struct sockaddr *)addr, sizeof(*addr)) < 0)
	  return -1;
     FD_ZERO(&fdset);
     FD_SET(fd, &fdset);
     timeout.tv_sec  = tmout;
     timeout.tv_usec = 0;
     ret = select (fd + 1, &fdset, NULL, NULL, &timeout);
     if (ret <= 0)
	  return -1;
     else {
	  int len;

	  if (ioctl (fd, FIONREAD, &nbytes) < 0)
	       return -1;

	  recv->data = malloc (nbytes);
	  ret = recvfrom (fd, recv->data, nbytes, 0, NULL, &len);
	  if (ret < 0) {
	       free (recv->data);
	       return -1;
	  }
	  recv->data = realloc (recv->data, ret);
	  recv->length  = ret;
	  return 0;
     }
}

krb5_error_code
krb5_sendto_kdc (krb5_context context,
		 const krb5_data *send,
		 const krb5_realm *realm,
		 krb5_data *receive)
{
     krb5_error_code err;
     char **hostlist, **hp, *p;
     struct hostent *hostent;
     int fd;
     int port;
     int i;

     port = krb5_getportbyname ("kerberos", "udp", htons(88));
     fd = socket (AF_INET, SOCK_DGRAM, 0);
     if (fd < 0) {
	  return errno;
     }

     err = krb5_get_krbhst (context, realm, &hostlist);
     if (err) {
	  close (fd);
	  return err;
     }

     for (i = 0; i < 3; ++i)
	 for (hp = hostlist; (p = *hp); ++hp) {
	       char *addr;
	       char *colon;

	       colon = strchr (p, ':');
	       if (colon)
		    *colon = '\0';
	       hostent = gethostbyname (p);
	       if(hostent == NULL)
		   continue;
	       if (colon)
		    *colon++ = ':';
	       while ((addr = *hostent->h_addr_list++)) {
		    struct sockaddr_in a;
		    
		    memset (&a, 0, sizeof(a));
		    a.sin_family = AF_INET;
		    if (colon) {
			 int tmp;

			 sscanf (colon, "%d", &tmp);
			 a.sin_port = htons(tmp);
		    } else
			 a.sin_port   = port;
		    a.sin_addr   = *((struct in_addr *)addr);
		    
		    if (send_and_recv (fd, context->kdc_timeout, 
				       &a, send, receive) == 0) {
			 close (fd);
			 krb5_free_krbhst (context, hostlist);
			 return 0;
		    }
	       }
	  }
     close (fd);
     krb5_free_krbhst (context, hostlist);
     return KRB5_KDC_UNREACH;
}
