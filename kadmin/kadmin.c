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

#include "kadmin_locl.h"
#include <sl.h>

RCSID("$Id$");

static char *config_file;
static char *keyfile;
static int local_flag;
static int help_flag;
static int version_flag;
static char *realm;
static char *admin_server;

static struct getargs args[] = {
    { 
	"config-file",	'c',	arg_string,	&config_file, 
	"location of config file",	"file" 
    },
    {
	"key-file",	'k',	arg_string, &keyfile, 
	"location of master key file", "file"
    },
    {	
	"realm",	'r',	arg_string,   &realm, 
	"realm to use", "realm" 
    },
    {	
	"admin-server",	'a',	arg_string,   &admin_server, 
	"server to contact", "host" 
    },
    {	"local", 'l', arg_flag, &local_flag, "local admin mode" },
    {	"help",		'h',	arg_flag,   &help_flag },
    {	"version",	'v',	arg_flag,   &version_flag }
};

static int num_args = sizeof(args) / sizeof(args[0]);

static SL_cmd commands[] = {
    { "add_new_key",	add_new_key, 	"add_new_key principal"},
    { "ank"},
    { "cpw",		cpw_entry, 	"cpw_entry principal..."},
    { "change_password"},
    { "passwd"},
    { "del_entry",	del_entry, 	"del_entry principal..."},
    { "delete" },
    { "ext_keytab",	ext_keytab, 	"ext_keytab principal..."},
    { "get_entry",	get_entry, 	"get_entry principal"},
    { "rename",		rename_entry, 	"rename source target"},
    { "modify",		mod_entry, 	"modify principal" },
    { "privileges",	get_privs},
    { "list_principals",list_princs, 	"list expression..." },
    { "help",		help, "help"},
    { "?"},
    { "exit",		exit_kadmin, "exit"},
    { NULL}
};

krb5_context context;
void *kadm_handle;

int
help(int argc, char **argv)
{
    sl_help(commands, argc, argv);
    return 0;
}

int
exit_kadmin (int argc, char **argv)
{
    return 1;
}

static void
usage(int ret)
{
    arg_printusage (args, num_args, "");
    exit (ret);
}

int
get_privs(int argc, char **argv)
{
    u_int32_t privs;
    char str[128];
    kadm5_ret_t ret;
    
    ret = kadm5_get_privs(kadm_handle, &privs);
    if(ret)
	krb5_warn(context, ret, "kadm5_get_privs");
    else{
	ret =_kadm5_privs_to_string(privs, str, sizeof(str));
	printf("%s\n", str);
    }
    return 0;
}

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_config_section *cf;
    kadm5_config_params conf;
    int optind = 0;
    int e;

    set_progname(argv[0]);

    krb5_init_context(&context);

    while((e = getarg(args, num_args, argc, argv, &optind)))
	warnx("error at argument `%s'", argv[optind]);

    if (help_flag)
	usage (0);

    if (version_flag)
	krb5_errx(context, 0, "%s", heimdal_version);

    argc -= optind;
    argv += optind;

    if (config_file == NULL)
	config_file = HDB_DB_DIR "/kdc.conf";

    if(krb5_config_parse_file(config_file, &cf) == 0) {
	const char *p = krb5_config_get_string (cf, "kdc", "key-file", NULL);
	if (p)
	    keyfile = strdup(p);
    }

    memset(&conf, 0, sizeof(conf));
    conf.realm = realm;
    conf.mask |= KADM5_CONFIG_REALM;
    krb5_set_default_realm(context, realm); /* XXX should be fixed
					       some other way */
    conf.admin_server = admin_server;
    conf.mask |= KADM5_CONFIG_ADMIN_SERVER;

    if(local_flag)
	ret = kadm5_s_init_with_password_ctx(context, 
					     KADM5_ADMIN_SERVICE,
					     "password",
					     KADM5_ADMIN_SERVICE,
					     &conf, 0, 0, 
					     &kadm_handle);
    else
	ret = kadm5_c_init_with_password_ctx(context, 
					     /* XXX these are not used */
					     "client",
					     "password", 
					     KADM5_ADMIN_SERVICE,
					     &conf, 0, 0, 
					     &kadm_handle);
    
    if(ret)
	krb5_err(context, 1, ret, "kadm5_init_with_password");
    if (argc != 0)
	exit(sl_command(commands, argc, argv));

    ret = sl_loop(commands, "kadmin> ") != 0;
    kadm5_destroy(kadm_handle);
    krb5_free_context(context);
    return ret;
}
