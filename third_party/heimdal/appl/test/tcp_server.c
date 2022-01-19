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

/*
 * A sample server that uses the Kerberos V5 API.
 *
 * See "Introduction to the Kerberos 5 API" in the Doxygen documentation
 * for a walkthrough of this code.
 */

#include "test_locl.h"
RCSID("$Id$");

/* The API needs one Kerberos context per thread. */
krb5_context context;

static int
proto (int sock, const char *service)
{
    krb5_auth_context auth_context;
    krb5_error_code status;
    krb5_principal server;
    krb5_ticket *ticket;
    char *name;
    char hostname[MAXHOSTNAMELEN];
    krb5_data packet;
    krb5_data data;
    uint32_t len, net_len;
    ssize_t n;

    /* Initialize the authentication context, to be used to authenticate the peer. */
    status = krb5_auth_con_init (context, &auth_context);
    if (status)
	krb5_err (context, 1, status, "krb5_auth_con_init");

    /* Extract the local and remote address from the socket into auth_context. */
    status = krb5_auth_con_setaddrs_from_fd (context,
					     auth_context,
					     &sock);
    if (status)
	krb5_err (context, 1, status, "krb5_auth_con_setaddrs_from_fd");

    if (gethostname (hostname, sizeof(hostname)) < 0)
	krb5_err (context, 1, errno, "gethostname");

    /* Create principal "server" for "service" on "hostname" (this host). */
    status = krb5_sname_to_principal (context,
				      hostname,
				      service,
				      KRB5_NT_SRV_HST,
				      &server);
    if (status)
	krb5_err (context, 1, status, "krb5_sname_to_principal");

    /*
     * Perform the server side of the sendauth protocol. On success, "ticket"
     * contains the authenticated credentials of the client.
     */
    status = krb5_recvauth (context,
			    &auth_context,
			    &sock,
			    VERSION,
			    server,
			    0,            /* flags */
			    keytab,
			    &ticket);
    if (status)
	krb5_err (context, 1, status, "krb5_recvauth");

    /* Extract the client name as a string. */
    status = krb5_unparse_name (context,
				ticket->client,
				&name);
    if (status)
	krb5_err (context, 1, status, "krb5_unparse_name");

    fprintf (stderr, "User is `%s'\n", name);
    free (name);

    krb5_data_zero (&data);
    krb5_data_zero (&packet);

    /*
     * Read the payload (encoded as length, value).
     */
    n = krb5_net_read (context, &sock, &net_len, 4);
    if (n == 0)
	krb5_errx (context, 1, "EOF in krb5_net_read");
    if (n < 0)
	krb5_err (context, 1, errno, "krb5_net_read");

    len = ntohl(net_len);

    krb5_data_alloc (&packet, len);

    n = krb5_net_read (context, &sock, packet.data, len);
    if (n == 0)
	krb5_errx (context, 1, "EOF in krb5_net_read");
    if (n < 0)
	krb5_err (context, 1, errno, "krb5_net_read");

    /*
     * Expect a KRB_SAFE message (authenticated, not encrypted)
     */
    status = krb5_rd_safe (context,
			   auth_context,
			   &packet,
			   &data,
			   NULL);
    if (status)
	krb5_err (context, 1, status, "krb5_rd_safe");

    fprintf (stderr, "safe packet: %.*s\n", (int)data.length,
	    (char *)data.data);

    /*
     * Read the payload (encoded as length, value).
     */
    n = krb5_net_read (context, &sock, &net_len, 4);
    if (n == 0)
	krb5_errx (context, 1, "EOF in krb5_net_read");
    if (n < 0)
	krb5_err (context, 1, errno, "krb5_net_read");

    len = ntohl(net_len);

    krb5_data_alloc (&packet, len);

    n = krb5_net_read (context, &sock, packet.data, len);
    if (n == 0)
	krb5_errx (context, 1, "EOF in krb5_net_read");
    if (n < 0)
	krb5_err (context, 1, errno, "krb5_net_read");

    /*
     * Expect a KRB_PRIV message (authenticated and encrypted)
     */
    status = krb5_rd_priv (context,
			   auth_context,
			   &packet,
			   &data,
			   NULL);
    if (status)
	krb5_err (context, 1, status, "krb5_rd_priv");

    fprintf (stderr, "priv packet: %.*s\n", (int)data.length,
	    (char *)data.data);

    return 0;
}

static int
doit (int port, const char *service)
{
    /* Block waiting for a connection. */
    mini_inetd (port, NULL);

    return proto (STDIN_FILENO, service);
}

/*
 * Process only one connection and then exit.
 */
int
main(int argc, char **argv)
{
    int port = server_setup(&context, argc, argv);
    krb5_error_code ret;

    ret = krb5_kt_have_content(context, keytab);
    if (ret)
        krb5_err (context, 1, ret, "krb5_kt_have_content");

    return doit (port, service);
}
