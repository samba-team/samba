/*
 * Copyright (c) 1997 - 1999 Kungliga Tekniska Högskolan
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
    { "max-ticket-life",  0,	arg_string,	NULL, "max ticket lifetime" },
    { "max-renewable-life",  0,	arg_string,	NULL,
      "max renewable lifetime" },
    { "attributes",	0,	arg_string,	NULL, "attributes" }
};

static int num_args = sizeof(args) / sizeof(args[0]);

static void
usage(void)
{
    arg_printusage (args, num_args, "ank", "principal");
}

int
add_new_key(int argc, char **argv)
{
    kadm5_principal_ent_rec princ;
    char pwbuf[1024];
    char *password = NULL;
    int rkey = 0;
    int optind = 0;
    int mask = 0;
    krb5_error_code ret;
    krb5_principal princ_ent	= NULL;
    char *max_ticket_life	= NULL;
    char *max_renewable_life	= NULL;
    char *attributes		= NULL;

    args[0].value = &rkey;
    args[1].value = &password;
    args[2].value = &max_ticket_life;
    args[3].value = &max_renewable_life;
    args[4].value = &attributes;
    
    if(getarg(args, num_args, argc, argv, &optind))
	goto usage;
    if(optind == argc)
	goto usage;
    memset(&princ, 0, sizeof(princ));
    ret = krb5_parse_name(context, argv[optind], &princ_ent);
    if (ret) {
	krb5_warn(context, ret, "krb5_parse_name");
	goto out;
    }
    princ.principal = princ_ent;
    mask |= KADM5_PRINCIPAL;
    if (set_entry(context, &princ, &mask,
		  max_ticket_life, max_renewable_life, attributes)) {
	goto out;
    }
    edit_entry(&princ, &mask);
    if(rkey){
	princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	mask |= KADM5_ATTRIBUTES;
	password = "hemlig";
    }
    if(password == NULL){
	char *princ_name;
	char *prompt;

	krb5_unparse_name(context, princ_ent, &princ_name);
	asprintf (&prompt, "%s's Password: ", princ_name);
	free (princ_name);
	ret = des_read_pw_string (pwbuf, sizeof(pwbuf), prompt, 1);
	free (prompt);
	if (ret)
	    goto out;
	password = pwbuf;
    }
    
    ret = kadm5_create_principal(kadm_handle, &princ, mask, password);
    if(ret)
	krb5_warn(context, ret, "kadm5_create_principal");
    if(rkey){
	krb5_keyblock *new_keys;
	int n_keys, i;
	ret = kadm5_randkey_principal(kadm_handle, princ_ent, 
				      &new_keys, &n_keys);
	if(ret){
	    krb5_warn(context, ret, "kadm5_randkey_principal");
	    n_keys = 0;
	}
	for(i = 0; i < n_keys; i++)
	    krb5_free_keyblock_contents(context, &new_keys[i]);
	free(new_keys);
	kadm5_get_principal(kadm_handle, princ_ent, &princ, 
			    KADM5_PRINCIPAL | KADM5_KVNO | KADM5_ATTRIBUTES);
	princ.attributes &= (~KRB5_KDB_DISALLOW_ALL_TIX);
	princ.kvno = 1;
	kadm5_modify_principal(kadm_handle, &princ, 
			       KADM5_ATTRIBUTES | KADM5_KVNO);
	kadm5_free_principal_ent(kadm_handle, &princ);
    }
out:
    if(princ_ent)
	krb5_free_principal(context, princ_ent);
    if(!rkey && password)
	memset(password, 0, strlen(password));
    return 0;
usage:
    usage();
    goto out;
}
