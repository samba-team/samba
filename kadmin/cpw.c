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

RCSID("$Id$");

static struct getargs args[] = {
    { "random-key",	'r',	arg_flag,	NULL, "set random key" },
    { "password",	'p',	arg_string,	NULL, "princial's password" },
};

static int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(void)
{
    arg_printusage(args, num_args, "principal...");
}

int
cpw_entry(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_principal princ;
    int i;
    int optind = 0;
    char *password = NULL, pwbuf[128], prompt[128], *pr;
    int rnd = 0;

    args[0].value = &rnd;
    args[1].value = &password;
    if(getarg(args, num_args, argc, argv, &optind)){
	usage();
	return 0;
    }
    argc -= optind;
    argv += optind;

    if(password == NULL)
	password = pwbuf;
    
    for(i = 0; i < argc; i++){
	ret = krb5_parse_name(context, argv[i], &princ);
	if(ret){
	    krb5_warn(context, ret, "krb5_parse_name(%s)", argv[i]);
	    continue;
	}
	if(rnd == 0){
	    if(password == pwbuf){
		krb5_unparse_name(context, princ, &pr);
		snprintf(prompt, sizeof(prompt), "%s's Password: ", pr);
		free(pr);
		ret = des_read_pw_string(pwbuf, sizeof(pwbuf), prompt, 1);
		if(ret){
		    printf("Verify failure\n");
		}
	    }
	    if(ret == 0){
		ret = kadm5_chpass_principal(kadm_handle, princ, password);
		if(ret)
		    krb5_warn(context, ret, "%s", argv[i]);
	    }
	    memset(pwbuf, 0, sizeof(pwbuf));
	}else{
	    krb5_keyblock *keys;
	    int num_keys;
	    ret = kadm5_randkey_principal(kadm_handle, princ, &keys, &num_keys);
	    if(ret)
		krb5_warn(context, ret, "%s", argv[i]);
	    else{
		for(i = 0; i < num_keys; i++)
		    krb5_free_keyblock(context, &keys[i]);
		free(keys);
	    }
	}
	krb5_free_principal(context, princ);
    }
    return 0;
}

