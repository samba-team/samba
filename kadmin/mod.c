/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#include "kadmin_locl.h"

RCSID("$Id$");

struct mod_entry_data {
    char *attr_str;
    char *max_life_str;
    char *max_rlife_str;
    char *expiration_str;
    char *pw_expiration_str;
    int new_kvno;
};

static int
do_mod_entry(krb5_principal principal, void *data)
{
    krb5_error_code ret;
    kadm5_principal_ent_rec princ;
    int mask = 0;
    struct mod_entry_data *e = data;
    
    memset (&princ, 0, sizeof(princ));
    ret = kadm5_get_principal(kadm_handle, principal, &princ,
			      KADM5_PRINCIPAL | KADM5_ATTRIBUTES | 
			      KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
			      KADM5_PRINC_EXPIRE_TIME |
			      KADM5_PW_EXPIRATION);
    if(ret) 
	return ret;

    if(e->max_life_str || e->max_rlife_str || 
       e->expiration_str || e->pw_expiration_str || e->attr_str || 
       e->new_kvno != -1) {
	ret = set_entry(context, &princ, &mask, 
			e->max_life_str, 
			e->max_rlife_str, 
			e->expiration_str, 
			e->pw_expiration_str, 
			e->attr_str);
	if(e->new_kvno != -1) {
	    princ.kvno = e->new_kvno;
	    mask |= KADM5_KVNO;
	}
	
    } else
	ret = edit_entry(&princ, &mask, NULL, 0);
    if(ret == 0) {
	ret = kadm5_modify_principal(kadm_handle, &princ, mask);
	if(ret)
	    krb5_warn(context, ret, "kadm5_modify_principal");
    }
    
    kadm5_free_principal_ent(kadm_handle, &princ);
    return 0;
}

int
mod_entry(int argc, char **argv)
{
    krb5_error_code ret;
    int optind;

    struct mod_entry_data data;
    int i;

    struct getargs args[] = {
	{"attributes",	'a',	arg_string, NULL, "Attributies",
	 "attributes"},
	{"max-ticket-life", 0,	arg_string, NULL, "max ticket lifetime",
	 "lifetime"},
	{"max-renewable-life",  0, arg_string,	NULL,
	 "max renewable lifetime", "lifetime" },
	{"expiration-time",	0,	arg_string, 
	 NULL, "Expiration time", "time"},
	{"pw-expiration-time",  0,	arg_string, 
	 NULL, "Password expiration time", "time"},
	{"kvno",  0,	arg_integer, 
	 NULL, "Key version number", "number"},
    };

    i = 0;
    data.attr_str = NULL;
    args[i++].value = &data.attr_str;
    data.max_life_str = NULL;
    args[i++].value = &data.max_life_str;
    data.max_rlife_str = NULL;
    args[i++].value = &data.max_rlife_str;
    data.expiration_str = NULL;
    args[i++].value = &data.expiration_str;
    data.pw_expiration_str = NULL;
    args[i++].value = &data.pw_expiration_str;
    data.new_kvno = -1;
    args[i++].value = &data.new_kvno;

    optind = 0;

    if(getarg(args, sizeof(args) / sizeof(args[0]), 
	      argc, argv, &optind)){
	arg_printusage(args, 
		       sizeof(args) / sizeof(args[0]), 
		       "mod",
		       "principal...");
	return -1;
    }
    
    argc -= optind;
    argv += optind;
    
    if (argc < 1) {
	printf ("Usage: mod [options] principal\n");
	return 0;
    }

    for(i = 0; i < argc; i++)
	ret = foreach_principal(argv[i], do_mod_entry, "mod", &data);

    return 0;
}

