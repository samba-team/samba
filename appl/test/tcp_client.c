/*
 * Copyright (c) 1997 - 1999 Kungliga Tekniska Högskolan
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

#include "test_locl.h"
RCSID("$Id$");

krb5_context context;

static int
proto (int sock, const char *hostname, const char *service)
{
    krb5_context context;
    krb5_auth_context auth_context;
    krb5_error_code status;
    krb5_principal server;
    krb5_data data;
    krb5_data packet;
    u_int32_t len, net_len;

    status = krb5_init_context(&context);
    if (status)
	errx (1, "krb5_init_context: %s",
	      krb5_get_err_text(context, status));

    status = krb5_auth_con_init (context, &auth_context);
    if (status)
	errx (1, "krb5_auth_con_init: %s",
	      krb5_get_err_text(context, status));

    status = krb5_auth_con_setaddrs_from_fd (context,
					     auth_context,
					     &sock);
    if (status)
	errx (1, "krb5_auth_con_setaddrs_from_fd: %s",
	      krb5_get_err_text(context, status));

    status = krb5_sname_to_principal (context,
				      hostname,
				      service,
				      KRB5_NT_SRV_HST,
				      &server);
    if (status)
	errx (1, "krb5_sname_to_principal: %s",
	      krb5_get_err_text(context, status));

    status = krb5_sendauth (context,
			    &auth_context,
			    &sock,
			    VERSION,
			    NULL,
			    server,
			    AP_OPTS_MUTUAL_REQUIRED,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    NULL);
    if (status)
	errx (1, "krb5_sendauth: %s",
	      krb5_get_err_text(context, status));

    data.data   = "hej";
    data.length = 3;

    krb5_data_zero (&packet);

    status = krb5_mk_safe (context,
			   auth_context,
			   &data,
			   &packet,
			   NULL);
    if (status)
	errx (1, "krb5_mk_safe: %s",
	      krb5_get_err_text(context, status));

    len = packet.length;
    net_len = htonl(len);

    if (krb5_net_write (context, &sock, &net_len, 4) != 4)
	err (1, "krb5_net_write");
    if (krb5_net_write (context, &sock, packet.data, len) != len)
	err (1, "krb5_net_write");

    data.data   = "hemligt";
    data.length = 7;

    krb5_data_free (&packet);

    status = krb5_mk_priv (context,
			   auth_context,
			   &data,
			   &packet,
			   NULL);
    if (status)
	errx (1, "krb5_mk_priv: %s",
	      krb5_get_err_text(context, status));

    len = packet.length;
    net_len = htonl(len);

    if (krb5_net_write (context, &sock, &net_len, 4) != 4)
	err (1, "krb5_net_write");
    if (krb5_net_write (context, &sock, packet.data, len) != len)
	err (1, "krb5_net_write");
    return 0;
}

static int
doit (const char *hostname, int port, const char *service)
{
    struct hostent *hostent = NULL;
    char **h;
    int error;
    int af;

#ifdef HAVE_IPV6    
    if (hostent == NULL)
	hostent = getipnodebyname (hostname, AF_INET6, 0, &error);
#endif
    if (hostent == NULL)
	hostent = getipnodebyname (hostname, AF_INET, 0, &error);

    if (hostent == NULL)
	errx(1, "gethostbyname '%s' failed: %s", hostname, hstrerror(error));

    af = hostent->h_addrtype;

    for (h = hostent->h_addr_list; *h != NULL; ++h) {
	struct sockaddr_storage sa_ss;
	struct sockaddr *sa = (struct sockaddr *)&sa_ss;
	int s;

	sa->sa_family = af;
	socket_set_address_and_port (sa, *h, port);

	s = socket (af, SOCK_STREAM, 0);
	if (s < 0)
	    err (1, "socket");
	if (connect (s, sa, socket_sockaddr_size(sa)) < 0) {
	    warn ("connect(%s)", hostname);
	    close (s);
	    continue;
	}
	return proto (s, hostname, service);
    }
    return 1;
}

int
main(int argc, char **argv)
{
    int port = client_setup(&context, &argc, argv);
    return doit (argv[argc], port, service);
}
