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

struct timeval now;

hdb_entry*
db_fetch(krb5_principal principal)
{
    HDB *db;
    hdb_entry *ent;
    krb5_error_code ret;

    ret = hdb_open(context, &db, database, O_RDONLY, 0);
    if (ret) {
	kdc_log(0, "Failed to open database: %s", 
		krb5_get_err_text(context, ret));
	return NULL;
    }
    ALLOC(ent);
    ent->principal = principal;
    ret = db->fetch(context, db, ent);
    db->close(context, db);
    if(ret){
	free(ent);
	return NULL;
    }
    return ent;
}

static des_key_schedule master_key;
static int master_key_set;

void
set_master_key(EncryptionKey *key)
{
    if(key->keytype != KEYTYPE_DES || key->keyvalue.length != 8)
	abort();
    des_set_random_generator_seed(key->keyvalue.data);
    des_set_key(key->keyvalue.data, master_key);
    master_key_set = 1;
}

Key *
unseal_key(Key *key)
{
    Key *new;
    if(master_key_set){
	new = hdb_unseal_key(key, master_key);
    }else{
	new = ALLOC(new);
	copy_Key(key, new);
    }
    return new;
}
