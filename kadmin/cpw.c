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

#include "kadmin_locl.h"

RCSID("$Id$");

struct cpw_entry_data {
    int random;
    char *password;
};

static struct getargs args[] = {
    { "random-key",	'r',	arg_flag,	NULL, "set random key" },
    { "password",	'p',	arg_string,	NULL, "princial's password" },
};

static int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(void)
{
    arg_printusage(args, num_args, "cpw", "principal...");
}

static int
do_cpw_entry(krb5_principal principal, void *data)
{
    char *pw, pwbuf[128];
    struct cpw_entry_data *e = data;
    krb5_error_code ret = 0;
    
    pw = e->password;
    if(e->random == 0){
	if(pw == NULL){
	    char *princ_name;
	    char *prompt;

	    krb5_unparse_name(context, principal, &princ_name);
	    asprintf(&prompt, "%s's Password: ", princ_name);
	    free (princ_name);
	    ret = des_read_pw_string(pwbuf, sizeof(pwbuf), prompt, 1);
	    free (prompt);
	    if(ret){
		return 0; /* XXX error code? */
	    }
	    pw = pwbuf;
	}		
	if(ret == 0)
	    ret = kadm5_chpass_principal(kadm_handle, principal, pw);
	memset(pwbuf, 0, sizeof(pwbuf));
    }else{
	int i;
	krb5_keyblock *keys;
	int num_keys;
	ret = kadm5_randkey_principal(kadm_handle, principal, &keys, &num_keys);
	if(ret)
	    return ret;
	for(i = 0; i < num_keys; i++)
	    krb5_free_keyblock_contents(context, &keys[i]);
	free(keys);
    }
    return ret;
}

int
cpw_entry(int argc, char **argv)
{
    krb5_error_code ret;
    int i;
    int optind = 0;
    struct cpw_entry_data data;

    data.random = 0;
    data.password = NULL;

    args[0].value = &data.random;
    args[1].value = &data.password;
    if(getarg(args, num_args, argc, argv, &optind)){
	usage();
	return 0;
    }
    argc -= optind;
    argv += optind;

    for(i = 0; i < argc; i++)
	ret = foreach_principal(argv[i], do_cpw_entry, &data);

    return 0;
}

