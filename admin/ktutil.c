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

#include "ktutil_locl.h"

RCSID("$Id$");

int
kt_list(int argc, char **argv)
{
    krb5_keytab kt;
    krb5_error_code ret;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    if(argc == 1){
	ret = krb5_kt_default(context, &kt);
	if(ret){
	    krb5_warn(context, ret, "krb5_kt_default");
	    return 1;
	}
    } else if(argc == 2){
	ret = krb5_kt_resolve(context, argv[1], &kt);
	if(ret){
	    krb5_warn(context, ret, "krb5_kt_resolve(%s)", argv[1]);
	    return 1;
	}
    } else {
	krb5_warnx(context, "Usage: ktlist [keytab]");
	return 1;
    }
    ret = krb5_kt_start_seq_get(context, kt, &cursor);
    if(ret){
	krb5_warn(context, ret, "krb5_kt_start_seq_get");
	krb5_kt_close(context, kt);
	return 1;
    }
    printf("%s", "Version");
    printf("  ");
    printf("%-6s", "Type");
    printf("  ");
    printf("%s", "Principal");
    printf("\n");
    while((ret = krb5_kt_next_entry(context, kt, &entry, &cursor)) == 0){
	char *p;
	printf("   %3d ", entry.vno);
	printf("  ");
	krb5_keytype_to_string(context, entry.keyblock.keytype, &p);
	printf("%-6s", p);
	free(p);
	printf("  ");
	krb5_unparse_name(context, entry.principal, &p);
	printf("%s ", p);
	free(p);
	printf("\n");
	krb5_kt_free_entry(context, &entry);
    }
    ret = krb5_kt_end_seq_get(context, kt, &cursor);
    ret = krb5_kt_close(context, kt);
    return 0;
}

static int help(int argc, char **argv);

static SL_cmd cmds[] = {
    { "list",		kt_list,	"list [keytab]",	"" },
    { "srvconvert",	srvconv,	"srvconvert [flags]",	"" },
    { "srv2keytab" },
    { "help",		help,		"help",			"" },
    { NULL, 	NULL,		NULL, 			NULL }
};

static int help_flag;
static int version_flag;
 

static struct getargs args[] = {
    { "version",    0,     arg_flag, &version_flag, NULL, NULL },
    { "help",	    'h',   arg_flag, &help_flag, NULL, NULL}
};

static int num_args = sizeof(args) / sizeof(args[0]);

krb5_context context;

static int
help(int argc, char **argv)
{
    sl_help(cmds, argc, argv);
    return 0;
}

static void
usage(int status)
{
    arg_printusage(args, num_args, "command");
    exit(status);
}

int
main(int argc, char **argv)
{
    int optind = 0;
    set_progname(argv[0]);
    krb5_init_context(&context);
    if(getarg(args, num_args, argc, argv, &optind))
	usage(1);
    if(help_flag)
	usage(0);
    if(version_flag)
	krb5_errx(context, 0, "%s", heimdal_version);
    argc -= optind;
    argv += optind;
    if(argc == 0)
	usage(1);
    return sl_command(cmds, argc, argv);
}
