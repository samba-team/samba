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

#include "ktutil_locl.h"

RCSID("$Id$");

static int help_flag;
static int version_flag;
static int verbose_flag;
static char *keytab_string; 

static int
kt_list(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if(ret){
	krb5_warn(context, ret, "krb5_kt_start_seq_get");
	return 1;
    }
    printf("%s", "Version");
    printf("  ");
    printf("%-15s", "Type");
    printf("  ");
    printf("%s", "Principal");
    printf("\n");
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
	char *p;
	printf("   %3d ", entry.vno);
	printf("  ");
	ret = krb5_enctype_to_string(context, entry.keyblock.keytype, &p);
	if (ret != 0) 
	    asprintf(&p, "unknown (%d)", entry.keyblock.keytype);
	printf("%-15s", p);
	free(p);
	printf("  ");
	krb5_unparse_name(context, entry.principal, &p);
	printf("%s ", p);
	free(p);
	printf("\n");
	krb5_kt_free_entry(context, &entry);
    }
    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    return 0;
}

static int
kt_remove(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_keytab_entry entry;
    char *principal_string = NULL;
    krb5_principal principal = NULL;
    int kvno = 0;
    char *keytype_string = NULL;
    krb5_enctype enctype = 0;
    int help_flag = 0;
    struct getargs args[] = {
	{ "principal", 'p', arg_string, NULL, "principal to remove" },
	{ "kvno", 'V', arg_integer, NULL, "key version to remove" },
	{ "enctype", 'e', arg_string, NULL, "enctype to remove" },
	{ "help", 'h', arg_flag, NULL }
    };
    int num_args = sizeof(args) / sizeof(args[0]);
    int optind = 0;
    int i = 0;
    args[i++].value = &principal_string;
    args[i++].value = &kvno;
    args[i++].value = &keytype_string;
    args[i++].value = &help_flag;
    if(getarg(args, num_args, argc, argv, &optind)) {
	arg_printusage(args, num_args, "ktutil remove", "");
	return 0;
    }
    if(help_flag) {
	arg_printusage(args, num_args, "ktutil remove", "");
	return 0;
    }
    if(principal_string) {
	ret = krb5_parse_name(context, principal_string, &principal);
	if(ret) {
	    krb5_warn(context, ret, "%s", principal_string);
	    return 0;
	}
    }
    if(keytype_string) {
	ret = krb5_string_to_enctype(context, keytype_string, &enctype);
	if(ret) {
	    int t;
	    if(sscanf(keytype_string, "%d", &t) == 1)
		enctype = t;
	    else {
		krb5_warn(context, ret, "%s", keytype_string);
		if(principal)
		    krb5_free_principal(context, principal);
		return 0;
	    }
	}
    }
    if (!principal && !enctype && !kvno) {
	krb5_warnx(context, 
		   "You must give at least one of "
		   "principal, enctype or kvno.");
	return 0;
    }
    entry.principal = principal;
    entry.keyblock.keytype = enctype;
    entry.vno = kvno;
    ret = krb5_kt_remove_entry(context, keytab, &entry);
    if(ret)
	krb5_warn(context, ret, "remove");
    if(principal)
	krb5_free_principal(context, principal);
    return 0;
}

static int
kt_add(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_keytab_entry entry;
    char buf[128];
    char *principal_string = NULL;
    int kvno = -1;
    char *enctype_string = NULL;
    krb5_enctype enctype;
    char *password_string = NULL;
    int salt_flag = 1;
    int random_flag = 0;
    int help_flag = 0;
    struct getargs args[] = {
	{ "principal", 'p', arg_string, NULL, "principal of key", "principal"},
	{ "kvno", 'V', arg_integer, NULL, "key version of key" },
	{ "enctype", 'e', arg_string, NULL, "encryption type of key" },
	{ "password", 'w', arg_string, NULL, "password for key"},
	{ "salt", 's',	arg_negative_flag, NULL, "no salt" },
	{ "random",  'r', arg_flag, NULL, "generate random key" },
	{ "help", 'h', arg_flag, NULL }
    };
    int num_args = sizeof(args) / sizeof(args[0]);
    int optind = 0;
    int i = 0;
    args[i++].value = &principal_string;
    args[i++].value = &kvno;
    args[i++].value = &enctype_string;
    args[i++].value = &password_string;
    args[i++].value = &salt_flag;
    args[i++].value = &random_flag;
    args[i++].value = &help_flag;

    if(getarg(args, num_args, argc, argv, &optind)) {
	arg_printusage(args, num_args, "ktutil add", "");
	return 0;
    }
    if(help_flag) {
	arg_printusage(args, num_args, "ktutil add", "");
	return 0;
    }
    if(principal_string == NULL) {
	printf("Principal: ");
	if (fgets(buf, sizeof(buf), stdin) == NULL)
	    return 0;
	buf[strcspn(buf, "\r\n")] = '\0';
	principal_string = buf;
    }
    ret = krb5_parse_name(context, principal_string, &entry.principal);
    if(ret) {
	krb5_warn(context, ret, "%s", principal_string);
	return 0;
    }
    if(enctype_string == NULL) {
	printf("Encryption type: ");
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
	    krb5_free_principal (context, entry.principal);
	    return 0;
	}
	buf[strcspn(buf, "\r\n")] = '\0';
	enctype_string = buf;
    }
    ret = krb5_string_to_enctype(context, enctype_string, &enctype);
    if(ret) {
	int t;
	if(sscanf(enctype_string, "%d", &t) == 1)
	    enctype = t;
	else {
	    krb5_warn(context, ret, "%s", enctype_string);
	    krb5_free_principal(context, entry.principal);
	    return 0;
	}
    }
    if(kvno == -1) {
	printf("Key version: ");
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
	    krb5_free_principal (context, entry.principal);
	    return 0;
	}
	buf[strcspn(buf, "\r\n")] = '\0';
	kvno = atoi(buf);
    }
    if(password_string == NULL && random_flag == 0) {
	if(des_read_pw_string(buf, sizeof(buf), "Password: ", 1)) {
	    krb5_free_principal (context, entry.principal);
	    return 0;
	}
	password_string = buf;
    }
    if(password_string) {
	if (!salt_flag) {
	    krb5_salt salt;
	    krb5_data pw;

	    salt.salttype         = KRB5_PW_SALT;
	    salt.saltvalue.data   = NULL;
	    salt.saltvalue.length = 0;
	    pw.data = (void*)password_string;
	    pw.length = strlen(password_string);
	    krb5_string_to_key_data_salt(context, enctype, pw, salt,
					 &entry.keyblock);
        } else {
	    krb5_string_to_key(context, enctype, password_string, 
			       entry.principal, &entry.keyblock);
	}
	memset (password_string, 0, strlen(password_string));
    } else {
	krb5_generate_random_keyblock(context, enctype, &entry.keyblock);
    }
    entry.vno = kvno;
    ret = krb5_kt_add_entry(context, keytab, &entry);
    if(ret)
	krb5_warn(context, ret, "add");
    krb5_kt_free_entry(context, &entry);
    return 0;
}

static int
kt_get(int argc, char **argv)
{
    krb5_error_code ret;
    kadm5_config_params conf;
    void *kadm_handle;
    char *principal = NULL;
    char *realm = NULL;
    char *admin_server = NULL;
    int server_port = 0;
    int help_flag = 0;
    int optind = 0;
    int i, j;
    
    struct getargs args[] = {
	{ "principal",	'p',	arg_string,   NULL, 
	  "admin principal", "principal" 
	},
	{ "realm",	'r',	arg_string,   NULL, 
	  "realm to use", "realm" 
	},
	{ "admin-server",	'a',	arg_string, NULL,
	  "server to contact", "host" 
	},
	{ "server-port",	's',	arg_integer, NULL,
	  "server to contact", "port number" 
	},
	{ "help",		'h',	arg_flag,    NULL }
    };

    args[0].value = &principal;
    args[1].value = &realm;
    args[2].value = &admin_server;
    args[3].value = &server_port;
    args[4].value = &help_flag;

    memset(&conf, 0, sizeof(conf));

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optind)
       || help_flag) {
	arg_printusage(args, sizeof(args) / sizeof(args[0]), 
		       "ktutil get", "principal...");
	return 0;
    }
    
    if(realm) {
	krb5_set_default_realm(context, realm); /* XXX should be fixed
						   some other way */
	conf.realm = realm;
	conf.mask |= KADM5_CONFIG_REALM;
    }
    
    if (admin_server) {
	conf.admin_server = admin_server;
	conf.mask |= KADM5_CONFIG_ADMIN_SERVER;
    }

    if (server_port) {
	conf.kadmind_port = htons(server_port);
	conf.mask |= KADM5_CONFIG_KADMIND_PORT;
    }

    ret = kadm5_init_with_password_ctx(context, 
				       principal,
				       NULL,
				       KADM5_ADMIN_SERVICE,
				       &conf, 0, 0, 
				       &kadm_handle);
    if(ret) {
	krb5_warn(context, ret, "kadm5_init_with_password");
	return 0;
    }
    
    
    for(i = optind; i < argc; i++){
	krb5_principal princ_ent;
	kadm5_principal_ent_rec princ;
	int mask = 0;
	krb5_keyblock *keys;
	int n_keys;
	int created = 0;
	krb5_keytab_entry entry;

	ret = krb5_parse_name(context, argv[i], &princ_ent);
	memset(&princ, 0, sizeof(princ));
	princ.principal = princ_ent;
	mask |= KADM5_PRINCIPAL;
	princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	mask |= KADM5_ATTRIBUTES;
	princ.princ_expire_time = 0;
	mask |= KADM5_PRINC_EXPIRE_TIME;
	
	ret = kadm5_create_principal(kadm_handle, &princ, mask, "x");
	if(ret == 0)
	    created++;
	else if(ret != KADM5_DUP) {
	    krb5_free_principal(context, princ_ent);
	    continue;
	}
	ret = kadm5_randkey_principal(kadm_handle, princ_ent, &keys, &n_keys);
	
	ret = kadm5_get_principal(kadm_handle, princ_ent, &princ, 
			      KADM5_PRINCIPAL | KADM5_KVNO | KADM5_ATTRIBUTES);
	princ.attributes &= (~KRB5_KDB_DISALLOW_ALL_TIX);
	mask = KADM5_ATTRIBUTES;
	if(created) {
	    princ.kvno = 1;
	    mask |= KADM5_KVNO;
	}
	ret = kadm5_modify_principal(kadm_handle, &princ, mask);
	for(j = 0; j < n_keys; j++) {
	    entry.principal = princ_ent;
	    entry.vno = princ.kvno;
	    entry.keyblock = keys[j];
	    ret = krb5_kt_add_entry(context, keytab, &entry);
	    krb5_free_keyblock_contents(context, &keys[j]);
	}
	
	kadm5_free_principal_ent(kadm_handle, &princ);
	krb5_free_principal(context, princ_ent);
    }
    kadm5_destroy(kadm_handle);
    return 0;
}

static int
kt_copy (int argc, char **argv)
{
    krb5_error_code ret;
    int help_flag = 0;
    int optind = 0;
    krb5_keytab src_keytab, dst_keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    struct getargs args[] = {
	{ "help", 'h', arg_flag, NULL}
    };

    int num_args = sizeof(args) / sizeof(args[0]);
    int i = 0;

    args[i++].value = &help_flag;

    if(getarg(args, num_args, argc, argv, &optind)) {
	arg_printusage(args, num_args, "ktutil copy",
		       "keytab-src keytab-dest");
	return 0;
    }
    if (help_flag) {
	arg_printusage(args, num_args, "ktutil copy",
		       "keytab-src keytab-dest");
	return 0;
    }

    argv += optind;
    argc -= optind;

    if (argc != 2) {
	arg_printusage(args, num_args, "ktutil copy",
		       "keytab-src keytab-dest");
	return 0;
    }

    ret = krb5_kt_resolve (context, argv[0], &src_keytab);
    if (ret) {
	krb5_warn (context, ret, "resolving src keytab `%s'", argv[0]);
	return 0;
    }

    ret = krb5_kt_resolve (context, argv[1], &dst_keytab);
    if (ret) {
	krb5_kt_close (context, src_keytab);
	krb5_warn (context, ret, "resolving dst keytab `%s'", argv[1]);
	return 0;
    }

    ret = krb5_kt_start_seq_get (context, src_keytab, &cursor);
    if (ret) {
	krb5_warn (context, ret, "krb5_kt_start_seq_get");
	goto fail;
    }

    while((ret = krb5_kt_next_entry(context, src_keytab,
				    &entry, &cursor)) == 0) {
	ret = krb5_kt_add_entry (context, dst_keytab, &entry);
	if (verbose_flag) {
	    char *name_str;

	    krb5_unparse_name (context, entry.principal, &name_str);
	    printf ("copying %s\n", name_str);
	    free (name_str);
	}

	krb5_kt_free_entry (context, &entry);
	if (ret) {
	    krb5_warn (context, ret, "krb5_kt_add_entry");
	    break;
	}
    }
    krb5_kt_end_seq_get (context, src_keytab, &cursor);

fail:
    krb5_kt_close (context, src_keytab);
    krb5_kt_close (context, dst_keytab);
    return 0;
}

static int help(int argc, char **argv);

static SL_cmd cmds[] = {
    { "list",		kt_list,	"list",
      "shows contents of a keytab" },
    { "srvconvert",	srvconv,	"srvconvert [flags]",
      "convert v4 srvtab to keytab" },
    { "srv2keytab" },
    { "srvcreate",	srvcreate,	"srvcreate [flags]",
      "convert keytab to v4 srvtab" },
    { "key2srvtab" },
    { "add", 		kt_add,		"add",
      "adds key to keytab" },
    { "get", 		kt_get,		"get [principal...]",
      "create key in database and add to keytab" },
    { "remove", 	kt_remove,	"remove",
      "remove key from keytab" },
    { "copy",		kt_copy,	"copy src dst",
      "copy one keytab to another" },
    { "help",		help,		"help",			"" },
    { NULL, 	NULL,		NULL, 			NULL }
};

static struct getargs args[] = {
    { 
	"version",
	0,
	arg_flag,
	&version_flag,
	NULL,
	NULL 
    },
    { 
	"help",	    
	'h',   
	arg_flag, 
	&help_flag, 
	NULL, 
	NULL
    },
    { 
	"keytab",	    
	'k',   
	arg_string, 
	&keytab_string, 
	"keytab", 
	"keytab to operate on" 
    },
    {
	"verbose",
	'v',
	arg_flag,
	&verbose_flag,
	"verbose",
	"run verbosely"
    }
};

static int num_args = sizeof(args) / sizeof(args[0]);

krb5_context context;
krb5_keytab keytab;

static int
help(int argc, char **argv)
{
    sl_help(cmds, argc, argv);
    return 0;
}

static void
usage(int status)
{
    arg_printusage(args, num_args, NULL, "command");
    exit(status);
}

int
main(int argc, char **argv)
{
    int optind = 0;
    krb5_error_code ret;
    set_progname(argv[0]);
    krb5_init_context(&context);
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
    if(argc == 0)
	usage(1);
    if(keytab_string) {
	ret = krb5_kt_resolve(context, keytab_string, &keytab);
    } else {
	ret = krb5_kt_default(context, &keytab);
    }
    if(ret)
	krb5_err(context, 1, ret, "resolving keytab");
    ret = sl_command(cmds, argc, argv);
    if(ret == -1)
	krb5_warnx (context, "unrecognized command: %s", argv[0]);
    krb5_kt_close(context, keytab);
    return ret;
}
