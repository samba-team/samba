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
	       int udp,
	       const krb5_data *req,
	       krb5_data *rep)
{
     struct fd_set fdset;
     struct timeval timeout;
     int ret;
     int nbytes;

     if (send (fd, req->data, req->length, 0) < 0)
	  return -1;
     rep->data = NULL;
     rep->length = 0;
     do{
	 FD_ZERO(&fdset);
	 FD_SET(fd, &fdset);
	 timeout.tv_sec  = tmout;
	 timeout.tv_usec = 0;
	 ret = select (fd + 1, &fdset, NULL, NULL, &timeout);
	 if (ret <= 0)
	     return -1;
	 else {

	     if (ioctl (fd, FIONREAD, &nbytes) < 0)
		 return -1;
	     if(nbytes == 0)
		 return 0;

	     rep->data = realloc(rep->data, rep->length + nbytes);
	     ret = recv (fd, (char*)rep->data + rep->length, nbytes, 0);
	     if (ret < 0) {
		 free (rep->data);
		 return -1;
	     }
	     rep->length += ret;
	 }
     }while(!udp);
     return 0;
}

static int
send_and_recv_http(int fd, 
		   time_t tmout,
		   const krb5_data *send,
		   krb5_data *recv)
{
    char *request;
    char *str;
    krb5_data r;
    int ret;
    int len = base64_encode(send->data, send->length, &str);
    if(len < 0)
	return -1;
    asprintf(&request, "GET %s HTTP/1.1\r\n\r\n", str);
    free(str);
    r.data = request;
    r.length = strlen(request);
    ret = send_and_recv(fd, tmout, 0, &r, recv);
    free(request);
    if(ret)
	return ret;
    {
	char *s, *p;
	s = realloc(recv->data, recv->length + 1);
	s[recv->length] = 0;
	p = strstr(s, "\r\n\r\n");
	if(p == NULL)
	    return -1;
	p += 4;
	recv->data = s;
	recv->length -= p - s;
	memmove(recv->data, p, recv->length);
    }
    return 0;
}

static int
init_port(const char *s, int fallback)
{
    if (s) {
	int tmp;

	sscanf (s, "%d", &tmp);
	return htons(tmp);
    } else
	return fallback;
}

krb5_error_code
krb5_sendto_kdc (krb5_context context,
		 const krb5_data *send,
		 const krb5_realm *realm,
		 krb5_data *receive)
{
     krb5_error_code ret;
     char **hostlist, **hp, *p;
     struct hostent *hostent;
     int fd;
     int port;
     int i;
     char *buf;
     struct sockaddr *sa;

     port = krb5_getportbyname (context, "kerberos", "udp", 88);

     ret = krb5_get_krbhst (context, realm, &hostlist);
     if (ret) {
	  close (fd);
	  return ret;
     }

     buf = malloc(krb5_max_sockaddr_size ());
     if (buf == NULL) {
	 ret = ENOMEM;
	 goto out;
     }
     sa = (struct sockaddr *)buf;

     for (i = 0; i < context->max_retries; ++i)
	 for (hp = hostlist; (p = *hp); ++hp) {
	     char *addr;
	     char *colon;
	     int http_flag = 0;
	     int sa_size;

	     if(strncmp(p, "http://", 7) == 0){
		 p += 7;
		 http_flag = 1;
	     }
	     colon = strchr (p, ':');
	     if (colon)
		 *colon = '\0';
#ifdef HAVE_GETHOSTBYNAME2
	     hostent = gethostbyname2 (p, AF_INET6);
	     if (hostent == NULL)
		 hostent = gethostbyname2 (p, AF_INET);
#else
	     hostent = roken_gethostbyname (p);
#endif
	     if(hostent == NULL)
		 continue;
	     if (colon)
		 *colon++ = ':';
	     while ((addr = *hostent->h_addr_list++)) {
		 int family = hostent->h_addrtype;
		    
		 if(http_flag)
		     fd = socket(family, SOCK_STREAM, 0);
		 else
		     fd = socket(family, SOCK_DGRAM, 0);
		    
		 if(fd < 0) {
		     ret = errno;
		     goto out;
		 }
		 ret = krb5_h_addr2sockaddr (family,
					     addr,
					     sa,
					     &sa_size,
					     init_port(colon, port));
		 if (ret)
		     continue;

		 if(connect(fd, sa, sa_size) < 0) {
		     close (fd);
		     continue;
		 }
		    
		 if(http_flag)
		     ret = send_and_recv_http(fd, context->kdc_timeout,
					      send, receive);
		 else
			
		     ret = send_and_recv (fd, context->kdc_timeout, 1,
					  send, receive);
		 close (fd);
		 if(ret == 0 && receive->length != 0)
		     goto out;
	     }
	 }
     ret = KRB5_KDC_UNREACH;
out:
     krb5_free_krbhst (context, hostlist);
     free (buf);
     return ret;
}
