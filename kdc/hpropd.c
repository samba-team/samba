/*
 * Copyright (c) 1997, 1998, 1999 Kungliga Tekniska Högskolan
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

static int
open_socket(krb5_context context)
{
    int s, s2;
    int sin_len;
    struct sockaddr_in sin;
    int one = 1;

    sin_len = sizeof(sin);
    if(getpeername(0, (struct sockaddr*)&sin, &sin_len)){

	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s < 0){
	    krb5_warn(context, errno, "socket");
	    return -1;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = krb5_getportbyname (context, "hprop", "tcp", HPROP_PORT);
	if(bind(s, (struct sockaddr*)&sin, sizeof(sin)) < 0){
	    krb5_warn(context, errno, "bind");
	    close(s);
	    return -1;
	}
	if(listen(s, 5) < 0){
	    krb5_warn(context, errno, "listen");
	    close(s);
	    return -1;
	}

	s2 = accept(s, NULL, 0);
	if(s2 < 0)
	    krb5_warn(context, errno, "accept");
	close(s);
	return s2;
    }
    return 0;
}

static int help_flag;
static int version_flag;
static char *database = HDB_DEFAULT_DB;
static int from_stdin;

struct getargs args[] = {
#if 0
    { "slave",   's',  arg_strings, &slaves, "slave server", "host" },
#endif
    { "database", 'd', arg_string, &database, "database", "file" },
    { "stdin",    'n', arg_flag, &from_stdin , "read from stdin" },
    { "version",   0,  arg_flag, &version_flag, NULL, NULL },
    { "help",    'h',  arg_flag, &help_flag, NULL, NULL}
};

static int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int ret)
{
    arg_printusage (args, num_args, NULL, "");
    exit (ret);
}


int main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_auth_context ac = NULL;
    krb5_principal server;
    krb5_principal c1, c2;
    krb5_authenticator authent;
    krb5_keytab keytab;
    int fd;
    HDB *db;
    char hostname[128];
    int optind = 0;
    char *tmp_db;
    krb5_log_facility *fac;
    int nprincs;

    set_progname(argv[0]);

    ret = krb5_init_context(&context);
    if(ret) exit(1);

    ret = krb5_openlog(context, "hpropd", &fac);
    if(ret)
	;
    krb5_set_warn_dest(context, fac);
    
    if(getarg(args, num_args, argc, argv, &optind))
	usage(1);
    if(help_flag)
	usage(0);
    if(version_flag) {
	print_version(NULL);
	exit(0);
    }
    
    argc -= optind;
    argv += optind;

    if (argc != 0)
	usage(1);

    if(from_stdin)
	fd = STDIN_FILENO;
    else{
	fd = open_socket(context);
	if(fd < 0)
	    krb5_errx(context, 1, "Failed to obtain socket - exiting");
	
	{
	    int sin_len;
	    struct sockaddr_in sin;
	    sin_len = sizeof(sin);
	    if(getpeername(fd, (struct sockaddr*)&sin, &sin_len))
		krb5_err(context, 1, errno, "getpeername");
	    krb5_log(context, fac, 0, "Connection from %s", inet_ntoa(sin.sin_addr));
	}
    
	gethostname(hostname, sizeof(hostname));
	ret = krb5_sname_to_principal(context, hostname, HPROP_NAME, KRB5_NT_SRV_HST, &server);
	if(ret) krb5_err(context, 1, ret, "krb5_sname_to_principal");
	
	ret = krb5_kt_default(context, &keytab);
	if(ret) krb5_err(context, 1, ret, "krb5_kt_default");
	
	ret = krb5_recvauth(context, &ac, &fd, HPROP_VERSION, server, 0, keytab, NULL);
	if(ret) krb5_err(context, 1, ret, "krb5_recvauth");
	
	ret = krb5_auth_getauthenticator(context, ac, &authent);
	if(ret) krb5_err(context, 1, ret, "krb5_auth_getauthenticator");
	
	ret = krb5_make_principal(context, &c1, NULL, "kadmin", "hprop", NULL);
	if(ret) krb5_err(context, 1, ret, "krb5_make_principal");
	principalname2krb5_principal(&c2, authent->cname, authent->crealm);
	if(!krb5_principal_compare(context, c1, c2)){
	    char *s;
	    krb5_unparse_name(context, c2, &s);
	    krb5_errx(context, 1, "Unauthorized connection from %s", s);
	}
	krb5_free_principal(context, c1);
	krb5_free_principal(context, c2);

	ret = krb5_kt_close(context, keytab);
	if(ret) krb5_err(context, 1, ret, "krb5_kt_close");
    }
    
    asprintf(&tmp_db, "%s~", database);
    ret = hdb_create(context, &db, tmp_db);
    if(ret)
	krb5_err(context, 1, ret, "hdb_create(%s)", tmp_db);
    ret = db->open(context, db, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if(ret)
	krb5_err(context, 1, ret, "hdb_open(%s)", tmp_db);

    nprincs = 0;
    while(1){
	krb5_data data;
	hdb_entry entry;

	if(from_stdin){
	    ret = recv_clear(context, fd, &data);
	    if(ret) krb5_err(context, 1, ret, "recv_clear");
	}else{
	    ret = recv_priv(context, ac, fd, &data);
	    if(ret) krb5_err(context, 1, ret, "recv_priv");
	}

	if(data.length == 0){
	    if(!from_stdin){
		data.data = NULL;
		data.length = 0;
		send_priv(context, ac, &data, fd);
	    }
	    ret = db->rename(context, db, database);
	    if(ret) krb5_err(context, 1, ret, "db_rename");
	    ret = db->close(context, db);
	    if(ret) krb5_err(context, 1, ret, "db_close");
	    break;
	}
	ret = hdb_value2entry(context, &data, &entry);
	if(ret) krb5_err(context, 1, ret, "hdb_value2entry");
	ret = db->store(context, db, 0, &entry);
	if(ret == HDB_ERR_EXISTS){
	    char *s;
	    krb5_unparse_name(context, entry.principal, &s);
	    krb5_warnx(context, "Entry exists: %s", s);
	    free(s);
	} else if(ret) 
	    krb5_err(context, 1, ret, "db_store");
	else
	    nprincs++;
	hdb_free_entry(context, &entry);
    }
    krb5_log(context, fac, 0, "Received %d principals", nprincs);
    exit(0);
}
