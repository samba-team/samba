/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

/* Converts a database from version 0.0* to 0.1. This is done by
 * making three copies of each DES key (DES-CBC-CRC, DES-CBC-MD4, and
 * DES-CBC-MD5).
 *
 * Use with care. 
 */

#include "hdb_locl.h"
#include "getarg.h"

RCSID("$Id$");

static krb5_error_code
func(krb5_context context, HDB *db, hdb_entry *entry, void *data)
{
    int i;
    int n = 0;
    Key *k;
    int save_len;
    Key *save_val;
    HDB *new = data;
    krb5_error_code ret;

    for(i = 0; i < entry->keys.len; i++) 
	if(entry->keys.val[i].key.keytype == KEYTYPE_DES)
	    n += 2;
    k = malloc(sizeof(*k) * (entry->keys.len + n));
    n = 0;
    for(i = 0; i < entry->keys.len; i++) {
	copy_Key(&entry->keys.val[i], &k[n]);
	if(entry->keys.val[i].key.keytype == KEYTYPE_DES) {
	    copy_Key(&entry->keys.val[i], &k[n+1]);
	    k[n+1].key.keytype = ETYPE_DES_CBC_MD4;
	    copy_Key(&entry->keys.val[i], &k[n+2]);
	    k[n+2].key.keytype = ETYPE_DES_CBC_MD5;
	    n += 2;
	}
	n++;
    }
    save_len = entry->keys.len;
    save_val = entry->keys.val;
    entry->keys.len = n;
    entry->keys.val = k;
    ret = new->store(context, new, 1, entry);
    entry->keys.len = save_len;
    entry->keys.val = save_val;
    for(i = 0; i < n; i++) 
	free_Key(&k[n]);
    free(k);
    return 0;
}


char *old_database = HDB_DEFAULT_DB;
char *new_database = HDB_DEFAULT_DB ".new";
char *mkeyfile;
int help_flag;
int version_flag;

struct getargs args[] = {
    { "old-database",	0,	arg_string, &old_database,
      "name of database to convert", "file" },
    { "new-database",	0,	arg_string, &new_database,
      "name of converted database", "file" },
    { "master-key",	0,	arg_string, &mkeyfile, 
      "v5 master key file", "file" },
    { "help",		'h',	arg_flag,   &help_flag },
    { "version",	0,	arg_flag,   &version_flag }
};

static int num_args = sizeof(args) / sizeof(args[0]);

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    HDB *db, *new;
    EncryptionKey key;
    int optind = 0;
    
    ret = krb5_init_context(&context);
    if(ret != 0)
	krb5_err(context, 1, ret, "krb5_init_context");
    
    if(getarg(args, num_args, argc, argv, &optind))
	krb5_std_usage(1, args, num_args);

    if(help_flag)
	krb5_std_usage(0, args, num_args);
    
    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    ret = hdb_create(context, &db, old_database);
    if(ret != 0)
	krb5_err(context, 1, ret, "hdb_create");

    ret = hdb_read_master_key(context, mkeyfile, &key);
    if(ret)
	krb5_err(context, 1, ret, "hdb_read_master_key");
    if(key.keytype == KEYTYPE_DES)
	key.keytype = ETYPE_DES_CBC_MD5;
    
    ret = hdb_set_master_key(context, db, key);
    if (ret)
	krb5_err(context, 1, ret, "hdb_set_master_key");
    ret = hdb_create(context, &new, new_database);
    if(ret != 0)
	krb5_err(context, 1, ret, "hdb_create");
    ret = hdb_set_master_key(context, db, key);
    if (ret)
	krb5_err(context, 1, ret, "hdb_set_master_key");
    ret = db->open(context, db, O_RDONLY, 0);
    if(ret)
	krb5_err(context, 1, ret, "%s", old_database);
    ret = db->open(context, new, O_CREAT|O_EXCL|O_RDWR, 0600);
    if(ret)
	krb5_err(context, 1, ret, "%s", new_database);
    ret = hdb_foreach(context, db, func, new);
    if(ret != 0)
	krb5_err(context, 1, ret, "hdb_foreach");
    db->close(context, db);
    new->close(context, new);
    krb5_warnx(context, "wrote converted database to `%s'", new_database);
    return 0;
}
