/*
 * Copyright (c) 1997 - 2000, 2007 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors
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
proto (int sock, const char *service)
{
    struct sockaddr_storage remote, local;
    socklen_t addrlen;
    krb5_address remote_addr, local_addr;
    krb5_ccache ccache;
    krb5_auth_context auth_context;
    krb5_error_code status;
    krb5_data packet;
    krb5_data data;
    krb5_data client_name;
    krb5_creds in_creds, *out_creds;

    addrlen = sizeof(local);
    if (getsockname (sock, (struct sockaddr *)&local, &addrlen) < 0
	|| addrlen > sizeof(local))
	err (1, "getsockname)");

    addrlen = sizeof(remote);
    if (getpeername (sock, (struct sockaddr *)&remote, &addrlen) < 0
	|| addrlen > sizeof(remote))
	err (1, "getpeername");

    status = krb5_auth_con_init (context, &auth_context);
    if (status)
	krb5_err(context, 1, status, "krb5_auth_con_init");

    status = krb5_sockaddr2address (context, (struct sockaddr *)&local, &local_addr);
    if (status)
	krb5_err(context, 1, status, "krb5_sockaddr2address(local)");
    status = krb5_sockaddr2address (context, (struct sockaddr *)&remote, &remote_addr);
    if (status)
	krb5_err(context, 1, status, "krb5_sockaddr2address(remote)");

    status = krb5_auth_con_setaddrs (context,
				     auth_context,
				     &local_addr,
				     &remote_addr);
    if (status)
	krb5_err(context, 1, status, "krb5_auth_con_setaddr");

    status = krb5_read_message(context, &sock, &client_name);
    if(status)
	krb5_err(context, 1, status, "krb5_read_message");

    memset(&in_creds, 0, sizeof(in_creds));
    status = krb5_cc_default(context, &ccache);
    if(status)
	krb5_err(context, 1, status, "krb5_cc_default");
    status = krb5_cc_get_principal(context, ccache, &in_creds.client);
    if(status)
	krb5_err(context, 1, status, "krb5_cc_get_principal");

    status = krb5_read_message(context, &sock, &in_creds.second_ticket);
    if(status)
	krb5_err(context, 1, status, "krb5_read_message");

    status = krb5_parse_name(context, client_name.data, &in_creds.server);
    if(status)
	krb5_err(context, 1, status, "krb5_parse_name");

    status = krb5_get_credentials(context, KRB5_GC_USER_USER, ccache,
				  &in_creds, &out_creds);
    if(status)
	krb5_err(context, 1, status, "krb5_get_credentials");
    krb5_cc_close(context, ccache);
    ccache = NULL;

    status = krb5_cc_default(context, &ccache);
    if(status)
	krb5_err(context, 1, status, "krb5_cc_default");

    status = krb5_sendauth(context,
			   &auth_context,
			   &sock,
			   VERSION,
			   in_creds.client,
			   in_creds.server,
			   AP_OPTS_USE_SESSION_KEY,
			   NULL,
			   out_creds,
			   ccache,
			   NULL,
			   NULL,
			   NULL);
    krb5_cc_close(context, ccache);
    ccache = NULL;

    if (status)
	krb5_err(context, 1, status, "krb5_sendauth");

    {
	char *str;
	krb5_unparse_name(context, in_creds.server, &str);
	printf ("User is `%s'\n", str);
	free(str);
	krb5_unparse_name(context, in_creds.client, &str);
	printf ("Server is `%s'\n", str);
	free(str);
    }

    krb5_free_principal(context, in_creds.client);
    krb5_free_principal(context, in_creds.server);

    krb5_data_zero (&data);
    krb5_data_zero (&packet);

    status = krb5_read_message(context, &sock, &packet);
    if(status)
	krb5_err(context, 1, status, "krb5_read_message");

    status = krb5_rd_safe (context,
			   auth_context,
			   &packet,
			   &data,
			   NULL);
    if (status)
	krb5_err(context, 1, status, "krb5_rd_safe");

    printf ("safe packet: %.*s\n", (int)data.length,
	    (char *)data.data);

    status = krb5_read_message(context, &sock, &packet);
    if(status)
	krb5_err(context, 1, status, "krb5_read_message");

    status = krb5_rd_priv (context,
			   auth_context,
			   &packet,
			   &data,
			   NULL);
    if (status)
	krb5_err(context, 1, status, "krb5_rd_priv");

    printf ("priv packet: %.*s\n", (int)data.length,
	    (char *)data.data);

    return 0;
}

static int
doit (int port, const char *service)
{
    rk_socket_t sock;

    mini_inetd(port, &sock);

    return proto(sock, service);
}

int
main(int argc, char **argv)
{
    int port = server_setup(&context, argc, argv);
    return doit (port, service);
}
