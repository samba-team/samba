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

#include "kadm5_locl.h"

RCSID("$Id$");

#define set_value(X, V) do { if((X) == NULL) (X) = malloc(sizeof(*(X))); *(X) = V; } while(0);

kadm5_ret_t
_kadm5_setup_entry(hdb_entry *ent, kadm5_principal_ent_t princ, u_int32_t mask)
{
    if(mask & KADM5_PRINC_EXPIRE_TIME)
	set_value(ent->valid_end, princ->princ_expire_time);
    if(mask & KADM5_PW_EXPIRATION)
	set_value(ent->pw_end, princ->pw_expiration);
    if(mask & KADM5_ATTRIBUTES){
	ent->flags.postdate = 
	    !(princ->attributes & KRB5_KDB_DISALLOW_POSTDATED);
	ent->flags.forwardable = 
	    !(princ->attributes & KRB5_KDB_DISALLOW_FORWARDABLE);
	ent->flags.initial = 
	    !!(princ->attributes & KRB5_KDB_DISALLOW_TGT_BASED);
	ent->flags.renewable = 
	    !(princ->attributes & KRB5_KDB_DISALLOW_RENEWABLE);
	ent->flags.proxiable = 
	    !(princ->attributes & KRB5_KDB_DISALLOW_PROXIABLE);
	/* DUP_SKEY */
	ent->flags.invalid = 
	    !!(princ->attributes & KRB5_KDB_DISALLOW_ALL_TIX);
	ent->flags.require_preauth = 
	    !!(princ->attributes & KRB5_KDB_REQUIRES_PRE_AUTH);
	/* HW_AUTH */
	ent->flags.server = 
	    !(princ->attributes & KRB5_KDB_DISALLOW_SVR);
	ent->flags.change_pw = 
	    !!(princ->attributes & KRB5_KDB_PWCHANGE_SERVICE);
	/* SUPPPORT_DESMD5 */
	/* NEW_PRINC */
    
    }
    if(mask & KADM5_MAX_LIFE)
	set_value(ent->max_life, princ->max_life);
    if(mask & KADM5_KVNO)
	ent->kvno = princ->kvno;
    if(mask & KADM5_MAX_RLIFE)
	set_value(ent->max_renew, princ->max_renewable_life);
    if(mask & KADM5_TL_DATA){
	/* XXX */
    }
    if(mask & KADM5_FAIL_AUTH_COUNT){
	/* XXX */
    }
    return 0;
}
