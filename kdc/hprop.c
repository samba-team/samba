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

#include "hprop.h"

RCSID("$Id$");

int open_socket(const char *hostname)
{
    int s;
    struct hostent *hp;
    struct sockaddr_in sin;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0){
	warn("socket");
	return -1;
    }
    hp = gethostbyname(hostname);
    if(hp == NULL){
	warnx("%s: %s", hostname, hstrerror(h_errno));
	close(s);
	return -1;
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = krb5_getportbyname ("hprop", "tcp", htons(4712));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    if(connect(s, (struct sockaddr*)&sin, sizeof(sin)) < 0){
	warn("connect");
	close(s);
	return -1;
    }
    return s;
}

struct prop_data{
    krb5_auth_context auth_context;
    int sock;
};

int hdb_entry2value(krb5_context, hdb_entry*, krb5_data*);

krb5_error_code 
send_priv(krb5_context context, krb5_auth_context ac,
	  krb5_data *data, int fd)
{
    krb5_data packet;
    krb5_error_code ret;
    unsigned char net_len[4];

    ret = krb5_mk_priv (context,
			ac,
			data,
			&packet,
			NULL);
    if (ret)
	return ret;
    
    net_len[0] = (packet.length >> 24) & 0xff;
    net_len[1] = (packet.length >> 16) & 0xff;
    net_len[2] = (packet.length >> 8) & 0xff;
    net_len[3] = packet.length & 0xff;
	
    if (krb5_net_write (context, fd, net_len, 4) != 4)
	ret = errno;
    else if (krb5_net_write (context, fd, packet.data, packet.length) != packet.length)
	ret =  errno;
    krb5_data_free(&packet);
    return ret;
}

krb5_error_code
func(krb5_context context, HDB *db, hdb_entry *entry, void *appdata)
{
    krb5_error_code ret;
    struct prop_data *pd = appdata;
    krb5_data data;

    ret = hdb_entry2value(context, entry, &data);
    if(ret) return ret;

    ret = send_priv(context, pd->auth_context, &data, pd->sock);
    krb5_data_free(&data);
    return ret;
}

static getarg_strings slaves;
static int version_flag;
static int help_flag;
static char *ktname = HPROP_KEYTAB;

struct getargs args[] = {
#if 0
    { "slave",   's',  arg_strings, &slaves, "slave server", "host" },
#endif
    { "keytab",  'k',  arg_string, &ktname, "keytab to use for authentication", "keytab" },
    { "version",   0,  arg_flag, &version_flag, NULL, NULL },
    { "help",    'h',  arg_flag, &help_flag, NULL, NULL}
};

static int num_args = sizeof(args) / sizeof(args[0]);

void usage(int ret)
{
    arg_printusage (args, num_args, "host ...");
    exit (ret);
}

int main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_auth_context ac;
    krb5_principal client;
    krb5_principal server;
    krb5_creds creds;
    krb5_ccache ccache;
    krb5_keytab keytab;
    int fd;
    HDB *db;
    krb5_get_init_creds_opt init_opts;
    krb5_preauthtype preauth = KRB5_PADATA_ENC_TIMESTAMP;
    int optind = 0;
    int i;

    set_progname(argv[0]);

    if(getarg(args, num_args, argc, argv, &optind))
	usage(1);

    if(help_flag)
	usage(0);
    
    if(version_flag){
	fprintf(stderr, "%s (%s)\n", __progname, heimdal_version);
	exit(0);
    }

    ret = krb5_init_context(&context);
    if(ret)
	exit(1);

    ret = hdb_open(context, &db, NULL, O_RDONLY, 0);
    if(ret) krb5_err(context, 1, ret, "hdb_open");

    ret = krb5_kt_resolve(context, ktname, &keytab);
    if(ret) krb5_err(context, 1, ret, "krb5_kt_resolve");
    
    ret = krb5_make_principal(context, &client, NULL, "kadmin", HPROP_NAME, NULL);
    if(ret) krb5_err(context, 1, ret, "krb5_make_principal");

    krb5_get_init_creds_opt_init(&init_opts);
    krb5_get_init_creds_opt_set_preauth_list(&init_opts, &preauth, 1);

    ret = krb5_get_init_creds_keytab(context, &creds, client, keytab, 0, NULL, &init_opts);
    if(ret) krb5_err(context, 1, ret, "krb5_get_init_creds");
    
    ret = krb5_kt_close(context, keytab);
    if(ret) krb5_err(context, 1, ret, "krb5_kt_close");
    
    ret = krb5_cc_gen_new(context, &mcc_ops, &ccache);
    if(ret) krb5_err(context, 1, ret, "krb5_cc_gen_new");

    ret = krb5_cc_initialize(context, ccache, client);
    if(ret) krb5_err(context, 1, ret, "krb5_cc_initialize");

    ret = krb5_cc_store_cred(context, ccache, &creds);
    if(ret) krb5_err(context, 1, ret, "krb5_cc_store_cred");
    
    for(i = optind; i < argc; i++){
	fd = open_socket(argv[i]);
	if(fd < 0)
	    continue;

	ret = krb5_sname_to_principal(context, argv[i], HPROP_NAME, KRB5_NT_SRV_HST, &server);
	if(ret) {
	    krb5_warn(context, ret, "krb5_sname_to_principal(%s)", argv[i]);
	    close(fd);
	    continue;
	}
    
	ac = NULL;
	ret = krb5_sendauth(context,
			    &ac,
			    &fd,
			    HPROP_VERSION,
			    NULL,
			    server,
			    AP_OPTS_MUTUAL_REQUIRED,
			    NULL, /* in_data */
			    NULL, /* in_creds */
			    ccache,
			    NULL,
			    NULL,
			    NULL);

	if(ret){
	    krb5_warn(context, ret, "krb5_sendauth");
	    close(fd);
	    continue;
	}
	{
	    struct prop_data pd;
	    pd.auth_context = ac;
	    pd.sock = fd;
	
	    ret = hdb_foreach(context, db, func, &pd);
	}
	if(ret)
	    krb5_warn(context, ret, "krb5_sendauth");
	else {
	    krb5_data data;
	    data.data = NULL;
	    data.length = 0;
	    ret = send_priv(context, ac, &data, fd);
	}

	if(ret) krb5_warn(context, ret, "send_priv");
	krb5_auth_con_free(context, ac);
	close(fd);
    }
    exit(0);
}
