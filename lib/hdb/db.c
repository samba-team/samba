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

#include "hdb_locl.h"

RCSID("$Id$");

#ifdef HAVE_DB_H

krb5_error_code
DB_close(krb5_context context, HDB *db)
{
    DB *d = (DB*)db->db;
    d->close(d);
    free(db);
    return 0;
}

static krb5_error_code
DB_op(krb5_context context, HDB *db, hdb_entry *entry, int op)
{
    DB *d = (DB*)db->db;
    DBT key, value;
    krb5_data data;
    int err;

    hdb_principal2key(context, entry->principal, &data);
    key.data = data.data;
    key.size = data.length;
    switch(op){
    case 0:
	err = d->get(d, &key, &value, 0);
	break;
    case 1:
	hdb_entry2value(context, entry, &data);
	value.data = data.data;
	value.size = data.length;
	err = d->put(d, &key, &value, 0);
	krb5_data_free(&data);
	break;
    case 2:
	err = d->del(d, &key, 0);
	break;
    }
    data.data = key.data;
    data.length = key.size;
    krb5_data_free(&data);
    if(err < 0)
	return errno;
    if(err == 1)
	return KRB5_HDB_NOENTRY;
    if(op == 0){
	data.data = value.data;
	data.length = value.size;
	hdb_value2entry(context, &data, entry);
    }
    return 0;
}

static krb5_error_code
DB_fetch(krb5_context context, HDB *db, hdb_entry *entry)
{
    return DB_op(context, db, entry, 0);
}

static krb5_error_code
DB_store(krb5_context context, HDB *db, hdb_entry *entry)
{
    return DB_op(context, db, entry, 1);
}

static krb5_error_code
DB_delete(krb5_context context, HDB *db, hdb_entry *entry)
{
    return DB_op(context, db, entry, 2);
}

static krb5_error_code
DB_seq(krb5_context context, HDB *db, hdb_entry *entry, int flag)

{
    DB *d = (DB*)db->db;
    DBT key, value;
    krb5_data data;
    int err;

    err = d->seq(d, &key, &value, flag);
    if(err == -1)
	return errno;
    if(err == 1)
	return KRB5_HDB_NOENTRY;

    data.data = key.data;
    data.length = key.size;
    entry->principal = malloc(sizeof(*entry->principal));
    hdb_key2principal(context, &data, &entry->principal);
    data.data = value.data;
    data.length = value.size;
    hdb_value2entry(context, &data, entry);
    return 0;
}


static krb5_error_code
DB_firstkey(krb5_context context, HDB *db, hdb_entry *entry)
{
    return DB_seq(context, db, entry, R_FIRST);
}


static krb5_error_code
DB_nextkey(krb5_context context, HDB *db, hdb_entry *entry)
{
    return DB_seq(context, db, entry, R_NEXT);
}

krb5_error_code
hdb_db_open(krb5_context context, HDB **db, 
	    const char *filename, int flags, mode_t mode)
{
    DB *d;
    char *fn = malloc(strlen(filename) + 4);
    sprintf(fn, "%s.db", filename);
    d = dbopen(fn, flags, mode, DB_BTREE, NULL);
    free(fn);
    if(d == NULL)
	return errno;
    *db = malloc(sizeof(**db));
    (*db)->db = d;
    (*db)->close = DB_close;
    (*db)->fetch = DB_fetch;
    (*db)->store = DB_store;
    (*db)->delete = DB_delete;
    (*db)->firstkey = DB_firstkey;
    (*db)->nextkey= DB_nextkey;
    return 0;
}


#endif
