/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
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

#include "admin_locl.h"
#include <getarg.h>
#include <sl.h>

RCSID("$Id$");

static char *config_file;
static char *keyfile;
static int help_flag;
static int version_flag;

static struct getargs args[] = {
    { 
	"config-file",	'c',	arg_string,	&config_file, 
	"location of config file",	"file" 
    },
    {
	"key-file",	'k',	arg_string, &keyfile, 
	"location of master key file", "file"
    },
    {	"help",		'h',	arg_flag,   &help_flag },
    {	"version",	'v',	arg_flag,   &version_flag }
};

static int num_args = sizeof(args) / sizeof(args[0]);

static SL_cmd commands[] = {
    { "add_new_key",	add_new_key, "add_new_key principal"},
    { "ank"},
    { "add_random_key",	add_random_key, "add_random_key principal"},
    { "ark"},
    { "cpw",		passwd,   "passwd principal"},
    { "change_password"},
    { "passwd"},
    { "change_random_key", change_random_key, "change_random_key principal"},
    { "crk"},
    { "modify_entry",	mod_entry, "modify_entry principal"},
    { "dump",		dump, "dump [file]"},
    { "load",		load, "load file"},
    { "merge",		merge, "merge file"},
    { "help",		help, "help"},
    { "?"},
    { "init",		init, "init realm..."},
    { "get_entry",	get_entry, "get_entry principal"},
    { "delete",		del_entry, "delete principal"},
    { "ext_keytab",	ext_keytab, "ext_keytab principal"},
    { "exit",		exit_kdb_edit, "exit"},
    { "database",	set_db, "database [database]"},
    { "db" },
    { NULL}
};

krb5_context context;
char database[256] = HDB_DEFAULT_DB;
HDB *db = NULL;

int
help(int argc, char **argv)
{
    sl_help(commands, argc, argv);
    return 0;
}

int
exit_kdb_edit (int argc, char **argv)
{
    return 1;
}

int
set_db(int argc, char **argv)
{
    krb5_error_code ret;

    if (db)
	db->destroy(context, db);

    switch(argc){
    case 1:
	strcpy(database, HDB_DEFAULT_DB);
	break;
    case 2:
	strcpy(database, argv[1]);
	break;
    default:
	fprintf(stderr, "Usage: database [database]\n");
    }
    ret = hdb_create(context, &db, database);
    if (ret)
	krb5_err(context, 1, ret, "opening database %s", database);
    ret = hdb_set_master_key(context, db, keyfile);
    if (ret)
	krb5_err(context, 1, ret, "setting master key");
    return 0;
}

static void
usage(int ret)
{
    arg_printusage (args, num_args, "");
    exit (ret);
}

int
main(int argc, char **argv)
{
    krb5_config_section *cf;
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

    if (argc != 0)
	usage (1);

    if (config_file == NULL)
	config_file = HDB_DB_DIR "/kdc.conf";

    if(krb5_config_parse_file(config_file, &cf) == 0) {
	const char *p = krb5_config_get_string (context, 
						cf, 
						"kdc", 
						"key-file", 
						NULL);
	if (p)
	    keyfile = strdup(p);
    }

    set_db(1, NULL);

    return sl_loop(commands, "kdb_edit> ") != 0;
}
