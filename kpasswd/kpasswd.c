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
RCSID("$Id$");

static void
usage (void)
{
    errx (1, "Usage: %s [-p] [principal]", __progname);
}

static struct sockaddr_in
get_kdc_address (krb5_context context,
		 krb5_realm realm)
{
    krb5_error_code ret;
    struct sockaddr_in addr;
    struct hostent *hostent;
    char **hostlist;
    char *dot;

    ret = krb5_get_krbhst (context,
			   &realm,
			   &hostlist);
    if (ret)
	errx (1, "krb5_get_krbhst: %s",
	      krb5_get_err_text(context, ret));

    dot = strchr (*hostlist, ':');
    if (dot)
	*dot = '\0';

    hostent = gethostbyname (*hostlist);
    if (hostent == 0)
	errx (1, "gethostbyname '%s' failed: %s",
	      *hostlist, hstrerror(h_errno));

    krb5_free_krbhst (context, hostlist);

    memset (&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy (&addr.sin_addr, hostent->h_addr_list[0], sizeof(addr.sin_addr));
    addr.sin_port   = krb5_getportbyname ("kpasswd",
					  "udp",
					  htons(KPASSWD_PORT));

    return addr;
}

static int
send_request (krb5_context context,
	      krb5_auth_context *auth_context,
	      krb5_creds *creds,
	      int sock,
	      struct sockaddr_in addr,
	      char *passwd)
{
    krb5_error_code ret;
    krb5_data ap_req_data;
    krb5_data krb_priv_data;
    krb5_data passwd_data;
    size_t len;
    u_char header[6];
    u_char *p;
    struct iovec iov[3];
    struct msghdr msghdr;
    struct fd_set fdset;
    struct timeval tv;

    krb5_data_zero (&ap_req_data);

    ret = krb5_mk_req_extended (context,
				auth_context,
				AP_OPTS_MUTUAL_REQUIRED,
				NULL, /* in_data */
				creds,
				&ap_req_data);
    if (ret)
	errx (1, "krb5_mk_req_extended: %s",
	      krb5_get_err_text(context, ret));

    passwd_data.data   = passwd;
    passwd_data.length = strlen(passwd);

    krb5_data_zero (&krb_priv_data);

    ret = krb5_mk_priv (context,
			*auth_context,
			&passwd_data,
			&krb_priv_data,
			NULL);
    if (ret)
	errx (1, "krb5_mk_priv: %s",
	      krb5_get_err_text(context, ret));

    len = 6 + ap_req_data.length + krb_priv_data.length;
    p = header;
    *p++ = (len >> 8) & 0xFF;
    *p++ = (len >> 0) & 0xFF;
    *p++ = 0;
    *p++ = 1;
    *p++ = (ap_req_data.length >> 8) & 0xFF;
    *p++ = (ap_req_data.length >> 0) & 0xFF;

    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name       = &addr;
    msghdr.msg_namelen    = sizeof(addr);
    msghdr.msg_iov        = iov;
    msghdr.msg_iovlen     = sizeof(iov)/sizeof(*iov);
#if 0
    msghdr.msg_control    = NULL;
    msghdr.msg_controllen = 0;
#endif

    iov[0].iov_base    = header;
    iov[0].iov_len     = 6;
    iov[1].iov_base    = ap_req_data.data;
    iov[1].iov_len     = ap_req_data.length;
    iov[2].iov_base    = krb_priv_data.data;
    iov[2].iov_len     = krb_priv_data.length;

    if (sendmsg (sock, &msghdr, 0) < 0)
	err (1, "sendmsg");

    krb5_data_free (&ap_req_data);
    krb5_data_free (&krb_priv_data);

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_usec = 0;
    tv.tv_sec  = 3;

    ret = select (sock + 1, &fdset, NULL, NULL, &tv);
    return ret != 1;
}

static int
process_reply (krb5_context context,
	       krb5_auth_context auth_context,
	       int sock)
{
    krb5_error_code ret;
    u_char reply[BUFSIZ];
    size_t len;
    u_int16_t pkt_len, pkt_ver;
    krb5_data ap_rep_data;

    ret = recvfrom (sock, reply, sizeof(reply), 0, NULL, NULL);
    if (ret < 0)
	err (1, "recvfrom");
    len = ret;
    pkt_len = (reply[0] << 8) | (reply[1]);
    pkt_ver = (reply[2] << 8) | (reply[3]);

    if (pkt_len != len)
	errx (1, "wrong len in reply");
    if (pkt_ver != 0x0001)
	errx (1, "wrong version number (%d)", pkt_ver);

    ap_rep_data.data = reply + 6;
    ap_rep_data.length  = (reply[4] << 8) | (reply[5]);
  
    if (ap_rep_data.length) {
	u_int16_t result_code;
	krb5_ap_rep_enc_part *ap_rep;
	krb5_data result_data;
	krb5_data priv_data;
	u_char *p;

	ret = krb5_rd_rep (context,
			   auth_context,
			   &ap_rep_data,
			   &ap_rep);
	if (ret)
	    errx (1, "krb5_rd_rep: %s",
		  krb5_get_err_text(context, ret));

	krb5_free_ap_rep_enc_part (context, ap_rep);

	priv_data.data   = ap_rep_data.data + ap_rep_data.length;
	priv_data.length = len - ap_rep_data.length - 6;

	krb5_data_zero (&result_data);

	ret = krb5_rd_priv (context,
			    auth_context,
			    &priv_data,
			    &result_data,
			    NULL);
	if (ret)
	    errx (1, "krb5_rd_priv: %s",
		  krb5_get_err_text(context, ret));

	if (result_data.length < 2)
	    errx (1, "bad length in result");
	p = result_data.data;
      
	result_code = (p[0] << 8) | (p[1]);
	if (result_code == 0) {
	    printf ("succeeded\n");
	    return 0;
	} else {
	    printf ("failed: %.*s\n",
		    (int)result_data.length - 2,
		    (char *)result_data.data + 2);
	    return 1;
	}
    } else {
	KRB_ERROR error;
	size_t size;
      
	ret = decode_KRB_ERROR(reply + 6, len - 6, &error, &size);
	if (ret == 0) {
	    printf ("failed: %s\n", *(error.e_text));
	}
	return 1;
    }
}

static int
change_password (krb5_context context,
		 krb5_principal principal,
		 krb5_preauthtype *pre_auth_types)
{
    krb5_error_code ret;
    krb5_ccache ccache;
    char *residual;
    krb5_auth_context auth_context = NULL;
    char *p;
    krb5_creds cred, cred_out;
    krb5_principal server;
    char passwd[BUFSIZ];
    int sock;
    struct sockaddr_in addr;
    int i;

    asprintf (&residual, "FILE:/tmp/krb5cc_passwd_%u", (unsigned)getuid());

    ret = krb5_cc_resolve (context, residual, &ccache);
    if (ret)
	errx (1, "krb5_cc_resolve: %s", krb5_get_err_text(context, ret));
    free (residual);
  
    ret = krb5_cc_initialize (context, ccache, principal);
    if (ret)
	errx (1, "krb5_cc_initialize: %s",
	      krb5_get_err_text(context, ret));

    memset(&cred, 0, sizeof(cred));
    cred.client = principal;
    cred.times.endtime = 0;

    ret = krb5_build_principal_ext (context,
				    &server,
				    strlen(principal->realm),
				    principal->realm,
				    strlen("kadmin"),
				    "kadmin",
				    strlen("changepw"),
				    "changepw",
				    NULL);
    if (ret)
	errx (1, "krb5_build_principal_ext: %s",
	      krb5_get_err_text(context, ret));

    server->name.name_type = KRB5_NT_SRV_INST;

    krb5_copy_principal (context, principal, &cred.client);
    krb5_copy_principal (context, server, &cred.server);
    cred.times.endtime = time(NULL) + 300;

    {
	char *tmp;
	krb5_unparse_name(context, principal, &p);
	asprintf(&tmp, "%s's password: ", p);
	free (p);
	des_read_pw_string(passwd, sizeof(passwd), tmp, 0);
	free(tmp);
    }

    ret = krb5_get_in_tkt_with_password (context,
					 0,
					 NULL,
					 NULL,
					 pre_auth_types,
					 passwd,
					 ccache,
					 &cred,
					 NULL);
    if (ret)
	errx (1, "krb5_get_in_tkt_with_password: %s",
	      krb5_get_err_text(context, ret));
  
    des_read_pw_string (passwd, sizeof(passwd), "New password: ", 1);

    sock = socket (AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
	err (1, "socket");

    addr = get_kdc_address (context, principal->realm);

    cred.server = server;
    cred.client = principal;

    ret = krb5_cc_retrieve_cred (context,
				 ccache,
				 0, /* ignored */
				 &cred,
				 &cred_out);
    if (ret)
	errx (1, "krb5_cc_retrieve_cred: %s",
	      krb5_get_err_text(context, ret));



    for (i = 0; i < 5; ++i) {
	ret = send_request (context,
			    &auth_context,
			    &cred_out,
			    sock,
			    addr,
			    passwd);
	if (ret == 0)
	    break;
	fprintf (stderr, "Retrying\n");
    }
    if (i == 5)
	errx (1, "Did not manage to contact kdc");

    krb5_free_creds (context, &cred_out);

    ret = process_reply (context,
			 auth_context,
			 sock);

    krb5_cc_destroy (context, ccache);
    krb5_free_ccache (context, ccache);

    return ret;
}

int
main (int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_principal principal;
    krb5_preauthtype pre_auth_types[] = {KRB5_PADATA_ENC_TIMESTAMP};
    int c;
    int preauth = 1;

    set_progname (argv[0]);

    while ((c = getopt (argc, argv, "p")) != EOF) {
	switch (c) {
	case 'p':
	    preauth = 0;
	    break;
	default:
	    usage ();
	}
    }
    argc -= optind;
    argv += optind;

    ret = krb5_init_context (&context);
    if (ret)
	errx (1, "krb5_init_context: %s", krb5_get_err_text(context, ret));
  
    if(argv[0]) {
	ret = krb5_parse_name (context, argv[0], &principal);
	if (ret)
	    errx (1, "krb5_parse_name: %s", krb5_get_err_text(context, ret));
    } else {
	struct passwd *pw;
	char *realm;

	pw = getpwuid(getuid());

	ret = krb5_get_default_realm (context, &realm);
	if (ret)
	    errx (1, "krb5_get_default_realm: %s",
		  krb5_get_err_text(context, ret));

	ret = krb5_build_principal(context, &principal,
				   strlen(realm), realm,
				   pw->pw_name, NULL);
	if (ret)
	    errx (1, "krb5_build_principal: %s",
		  krb5_get_err_text(context, ret));
	free (realm);
    }

    ret = change_password (context,
			   principal,
			   preauth ? pre_auth_types : NULL);

    krb5_free_principal (context, principal);
    krb5_free_context (context);
    return 0;
}
