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

int
mod_entry(int argc, char **argv)
{
    kadm5_principal_ent_rec princ;
    int mask = 0;
    krb5_error_code ret;
    krb5_principal princ_ent = NULL;
    
    if (argc != 2) {
	printf ("Usage: mod principal\n");
	return 0;
    }

    krb5_parse_name(context, argv[1], &princ_ent);

    memset(&princ, 0, sizeof(princ));
    ret = kadm5_get_principal(kadm_handle, princ_ent, &princ, 
			      KADM5_PRINCIPAL | KADM5_ATTRIBUTES | 
			      KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
			      KADM5_PRINC_EXPIRE_TIME | KADM5_PW_EXPIRATION);
    if (ret) {
	printf ("no such principal: %s\n", argv[1]);
	krb5_free_principal (context, princ_ent);
	return 0;
    }
    
    edit_entry(&princ, &mask, NULL, 0);

    ret = kadm5_modify_principal(kadm_handle, &princ, mask);
    if(ret)
	krb5_warn(context, ret, "kadm5_modify_principal");
    if(princ_ent)
	krb5_free_principal(context, princ_ent);
    kadm5_free_principal_ent(kadm_handle, &princ);
    return 0;
}
