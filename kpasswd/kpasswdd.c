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

#include "kpasswd_locl.h"
#include <hdb.h>
RCSID("$Id$");

static void
syslog_and_die (const char *m, ...)
{
    va_list args;

    va_start(args, m);
    vsyslog (LOG_ERR, m, args);
    va_end(args);
    exit (1);
}

static char *database = HDB_DEFAULT_DB;

static void
change (krb5_context context,
	krb5_principal principal,
	krb5_data *pwd_data)
{
    krb5_error_code ret;
    char *c;
    HDB *db;
    hdb_entry ent;
    krb5_data salt;

    krb5_unparse_name (context, principal, &c);

    syslog (LOG_INFO, "Changing password for %s", c);
    free (c);

    ret = hdb_open (context, &db, database, O_RDWR, 0600);
    if (ret) {
	syslog (LOG_ERR, "hdb_open: %s", krb5_get_err_text(context, ret));
	return;
    }

    ent.principal = principal;

    ret = db->fetch (context, db, &ent);
    
    switch (ret) {
    case KRB5_HDB_NOENTRY:
	syslog (LOG_ERR, "not found in database");
	return;
    case 0:
	break;
    default :
	syslog (LOG_ERR, "dbfetch: %s", krb5_get_err_text(context, ret));
	return;
    }

    krb5_data_zero (&salt);
    krb5_get_salt (principal, &salt);
    memset (&ent.keyblock, 0, sizeof(ent.keyblock));
    {
	char *pwd;

	pwd = malloc (pwd_data->length + 1);
	strcpy (pwd, pwd_data->data);
	pwd[pwd_data->length] = '\0';
	krb5_string_to_key (pwd, &salt, &ent.keyblock);
	free (pwd);
    }
    krb5_data_free (&salt);
    ent.kvno++;
    ent.last_change = time(NULL);
    krb5_copy_principal (context, principal, &ent.changed_by);
    ret = db->store (context, db, &ent);
    if (ret == -1) {
	syslog (LOG_ERR, "dbstore: %m");
	return;
    }
    hdb_free_entry (context, &ent);
    db->close (context, db);
}


static void
process (krb5_context context,
	 krb5_principal server,
	 int s,
	 struct sockaddr_in *addr,
	 u_char *msg,
	 int len)
{
    krb5_error_code ret;
    krb5_auth_context auth_context = NULL;
    u_int16_t pkt_len, pkt_ver, ap_req_len;

    krb5_data ap_req_data;
    krb5_data krb_priv_data;
    krb5_data out_data;
    krb5_ticket *ticket;

    pkt_len = (msg[0] << 8) | (msg[1]);
    pkt_ver = (msg[2] << 8) | (msg[3]);
    ap_req_len = (msg[4] << 8) | (msg[5]);
    if (pkt_len != len) {
	syslog (LOG_ERR, "Strange len: %d != %d", pkt_len, len);
	return;
    }
    if (pkt_ver != 0x0001) {
	syslog (LOG_ERR, "Bad version (%d)", pkt_ver);
	return;
    }

    ap_req_data.data   = msg + 6;
    ap_req_data.length = ap_req_len;

    ret = krb5_rd_req (context,
		       &auth_context,
		       &ap_req_data,
		       server,
		       NULL,
		       NULL,
		       &ticket);
    if (ret) {
	syslog (LOG_ERR, "krb5_rd_req: %s",
		krb5_get_err_text(context, ret));
	return;
    }

    if (!ticket->ticket.flags.initial) {
	syslog (LOG_ERR, "initial flag not set");
	return;
    }
    krb_priv_data.data   = msg + 6 + ap_req_len;
    krb_priv_data.length = len - 6 - ap_req_len;

    krb5_data_zero (&out_data);

    ret = krb5_rd_priv (context,
			auth_context,
			&krb_priv_data,
			&out_data,
			NULL);
    
    if (ret) {
	syslog (LOG_ERR, "krb5_rd_priv: %s",
		krb5_get_err_text(context, ret));
	return;
    }

    change (context, ticket->client, &out_data);

    krb5_auth_con_free (context, auth_context);
}

static void
doit (int port)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_principal server;
    struct sockaddr_in addr;
    int s;
    char *realm;

    ret = krb5_init_context (&context);
    if (ret)
	syslog_and_die ("krb5_init_context: %s",
			krb5_get_err_text(context, ret));

    ret = krb5_get_default_realm (context, &realm);
    if (ret)
	syslog_and_die ("krb5_get_default_realm: %s",
			krb5_get_err_text(context, ret));

    ret = krb5_build_principal_ext (context,
				    &server,
				    strlen(realm),
				    realm,
				    strlen("kadmin"),
				    "kadmin",
				    strlen("changepw"),
				    "changepw",
				    NULL);
    if (ret)
	syslog_and_die ("krb5_build_principal_ext: %s",
			krb5_get_err_text(context, ret));

    free (realm);

    s = socket (AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
	syslog_and_die ("socket: %m");
    memset (&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = port;
    if (bind (s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	syslog_and_die ("bind: %m");
    for (;;) {
	struct sockaddr_in other_addr;
	u_char buf[BUFSIZ];
	int ret;
	int addrlen = sizeof(other_addr);

	ret = recvfrom (s, buf, sizeof(buf), 0,
			(struct sockaddr *)&other_addr,
			&addrlen);
	if (ret < 0)
	    if(errno == EINTR)
		continue;
	    else
		syslog_and_die ("recvfrom: %m");
	process (context, server, s, &other_addr, buf, ret);
    }
}

int
main (int argc, char **argv)
{
    set_progname (argv[0]);
    openlog ("kpasswdd", LOG_ODELAY | LOG_PID, LOG_AUTH);

    doit (krb5_getportbyname ("kpasswd", "udp", htons(KPASSWD_PORT)));
    return 0;
}
