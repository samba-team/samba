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

#include "headers.h"
#include <getarg.h>

RCSID("$Id$");

int version5;
int version4;
int afs;
char *principal;
char *cell;
char *password;
char *keytype_str = "des";
int version;
int help;

struct getargs args[] = {
    { "version5", '5', arg_flag,   &version5, "Output Kerberos v5 string-to-key" },
    { "version4", '4', arg_flag,   &version4, "Output Kerberos v4 string-to-key" },
#ifdef KRB4
    { "afs",      'a', arg_flag,   &afs, "Output AFS string-to-key" },
    { "cell",     'c', arg_string, &cell, "AFS cell to use", "cell" },
#endif
    { "password", 'w', arg_string, &password, "Password to use", "password" },
    { "principal",'p', arg_string, &principal, "Kerberos v5 principal to use", "principal" },
    { "keytype",  'k', arg_string, &keytype_str, "Keytype" },
    { "version",    0, arg_flag,   &version, "print version" },
    { "help",       0, arg_flag,   &help, NULL }
};

int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(int status)
{
    arg_printusage (args, num_args, "password");
    exit(status);
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_principal princ;
    krb5_data salt;
    krb5_keyblock key;
    int i;
    int optind;
    char buf[1024];
    krb5_keytype keytype;
    krb5_error_code ret;

    set_progname(argv[0]);
    krb5_init_context(&context);
    optind = 0;
    if(getarg(args, num_args, argc, argv, &optind))
	usage(1);
    
    if(help)
	usage(0);
    
    if(version){
	fprintf(stderr, "string2key (%s-%s)\n", PACKAGE, VERSION);
	exit(0);
    }

    argc -= optind;
    argv += optind;

    if (argc > 1)
	usage(1);

    if(!version5 && !version4 && !afs)
	version5 = 1;

    ret = krb5_string_to_keytype(context, keytype_str, &keytype);
    if(ret)
	krb5_err(context, 1, ret, "%s", keytype);
    
    if(keytype != KEYTYPE_DES && (afs || version4))
	krb5_errx(context, 1, 
		  "DES is the only valid keytype for AFS and Kerberos 4");
    

    if(version5 && principal == NULL){
	printf("Kerberos v5 principal: ");
	fgets(buf, sizeof(buf), stdin);
	buf[strlen(buf) - 1] = 0;
	principal = strdup(buf);
    }
#ifdef KRB4
    if(afs && cell == NULL){
	printf("AFS cell: ");
	fgets(buf, sizeof(buf), stdin);
	buf[strlen(buf) - 1] = 0;
	cell = strdup(buf);
    }
#endif
    if(argv[0])
	password = argv[0];
    if(password == NULL){
	des_read_pw_string(buf, sizeof(buf), "Password: ", 0);
	password = buf;
    }
	
    if(version5){
	krb5_parse_name(context, principal, &princ);
	salt.length = 0;
	salt.data = NULL;
	krb5_get_salt(princ, &salt);
	krb5_string_to_key(password, &salt, keytype, &key);
	printf("Kerberos v5 key: ");
	for(i = 0; i < key.keyvalue.length; i++)
	    printf("%02x", ((unsigned char*)key.keyvalue.data)[i]);
	printf("\n");
    }
    if(version4){
	des_cblock key;
	des_string_to_key(password, &key);
	printf("Kerberos v4 key: ");
	for(i = 0; i < 8; i++)
	    printf("%02x", ((unsigned char*)key)[i]);
	printf("\n");
    }
#ifdef KRB4
    if(afs){
	des_cblock key;
	afs_string_to_key(password, cell, &key);
	printf("AFS key:         ");
	for(i = 0; i < 8; i++)
	    printf("%02x", ((unsigned char*)key)[i]);
	printf("\n");
    }
#endif
    return 0;
}
