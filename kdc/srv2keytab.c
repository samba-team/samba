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

#include "kdc_locl.h"

RCSID("$Id$");

/* convert a version 4 srvtab to a version 5 keytab */

#ifndef KEYFILE
#define KEYFILE "/etc/srvtab"
#endif

static char *srvtab = KEYFILE;
static char *keytab;
static int help_flag;
static int version_flag;
static int verbose;

static struct getargs args[] = {
    { "srvtab", 's', arg_string, &srvtab, "Srvtab to convert", "file" },
    { "keytab", 'k', arg_string, &keytab, "Keytab to put result in", "keytab" },
    { "help", 'h', arg_flag, &help_flag },
    { "version", 0, arg_flag, &version_flag },
    { "verbose", 'v', arg_flag, &verbose },
};

static int num_args = sizeof(args) / sizeof(args[0]);

void
usage(int code)
{
    arg_printusage(args, num_args, "");
    exit(code);
}

int main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    int optind = 0;
    char keytab_name[256];
    int fd;
    krb5_storage *sp;
    krb5_keytab id;

    set_progname(argv[0]);

    if(getarg(args, num_args, argc, argv, &optind))
	usage(1);
    if(help_flag)
	usage(0);
    if(version_flag)
	errx(0, "%s", heimdal_version);

    krb5_init_context(&context);
    if(keytab == NULL){
	ret = krb5_kt_default_name(context, keytab_name, sizeof(keytab_name));
	if(ret) krb5_err(context, 1, ret, "krb5_kt_default_name");
	keytab = keytab_name;
    }
    ret = krb5_kt_resolve(context, keytab, &id);
    if(ret) krb5_err(context, 1, ret, "krb5_kt_resolve");
    fd = open(srvtab, O_RDONLY);
    if(fd < 0)
	krb5_err(context, 1, errno, "%s", srvtab);
    sp = krb5_storage_from_fd(fd);
    while(1){
	char *service, *instance, *realm;
	int8_t kvno;
	des_cblock key;
	krb5_keytab_entry entry;
	
	ret = krb5_ret_stringz(sp, &service);
	if(ret == KRB5_CC_END)
	    break;
	if(ret) krb5_err(context, 1, ret, "reading service");
	ret = krb5_ret_stringz(sp, &instance);
	if(ret) krb5_err(context, 1, ret, "reading instance");
	ret = krb5_ret_stringz(sp, &realm);
	if(ret) krb5_err(context, 1, ret, "reading realm");
	ret = krb5_ret_int8(sp, &kvno);
	if(ret) krb5_err(context, 1, ret, "reading kvno");
	ret = sp->fetch(sp, key, 8);
	if(ret < 0)
	    krb5_err(context, 1, errno, "reading key");
	if(ret < 8)
	    krb5_err(context, 1, errno, "end if file while reading key");
	
	ret = krb5_425_conv_principal(context, service, instance, realm,
				      &entry.principal);
	if(ret) krb5_err(context, 1, ret, "krb5_425_conv_principal");
	entry.vno = kvno;
	entry.keyblock.keytype = KEYTYPE_DES;
	entry.keyblock.keyvalue.data = key;
	entry.keyblock.keyvalue.length = 8;
	
	if(verbose){
	    char *p;
	    ret = krb5_unparse_name(context, entry.principal, &p);
	    if(ret)
		krb5_warn(context, ret, "krb5_unparse_name");
	    else{
		fprintf(stderr, "Storing keytab for %s\n", p);
		free(p);
	    }
				    
	}
	ret = krb5_kt_add_entry(context, id, &entry);
	if(ret) krb5_err(context, 1, ret, "krb5_kt_add_entry");
	krb5_free_principal(context, entry.principal);
    }
    
    
}
