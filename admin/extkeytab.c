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

#include "admin_locl.h"

RCSID("$Id$");

int 
ext_keytab(int argc, char **argv)
{
    hdb_entry ent;
    krb5_keytab kid;
    krb5_principal principal;
    krb5_error_code ret = 0;
    int i;
    
    if(argc < 2 || argc > 3){
	krb5_warnx(context, "Usage: ext_keytab principal [file]");
	return 0;
    }
    
    ret = db->open(context, db, O_RDONLY, 0600);
    if(ret){
	krb5_warn(context, ret, "hdb_open");
	return 0;
    }

    ret = krb5_parse_name (context, argv[1], &principal);
    if (ret) {
	krb5_warn(context, ret, "krb5_parse_name");
	goto cleanup1;
    }
    ent.principal = principal;

    ret = db->fetch(context, db, &ent);
    if (ret) {
	krb5_warn (context, ret, "db->fetch");
	krb5_free_principal (context, ent.principal);
	goto cleanup1;
    }

    { 
	char ktname[128] = "FILE:";
	if(argc == 3)
	    strcat(ktname, argv[2]);
	else
	    ret = krb5_kt_default_name(context, ktname, sizeof(ktname));
	ret = krb5_kt_resolve(context, ktname, &kid);
    }

    if (ret) {
	krb5_warn(context, ret, "krb5_kt_resolve");
	goto cleanup1;
    }

    for(i = 0; i < ent.keys.len; ++i) {
	krb5_keytab_entry key_entry;
	Key *k;

	krb5_copy_principal (context, principal, &key_entry.principal);
	key_entry.vno = ent.kvno;
	k = &ent.keys.val[i];

	key_entry.keyblock.keytype = k->key.keytype;
	key_entry.keyblock.keyvalue.length = 0;
	krb5_data_copy(&key_entry.keyblock.keyvalue,
		       k->key.keyvalue.data,
		       k->key.keyvalue.length);

	ret = krb5_kt_add_entry(context,
				kid,
				&key_entry);
	
	if (ret) {
	    krb5_free_principal (context, key_entry.principal);
	    krb5_free_keyblock (context, &key_entry.keyblock);
	    krb5_warn(context, ret, "krb5_kt_add_entry");
	    break;
	}
    }

    krb5_kt_close (context, kid);
    hdb_free_entry (context, &ent);
cleanup1:
    db->close (context, db);
    return ret;
}
