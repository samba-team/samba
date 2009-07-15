/*
 * Copyright (c) 1999 - 2002 Kungliga Tekniska Högskolan
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

#include "hdb_locl.h"

/* keytab backend for HDB databases */

struct hdb_data {
    char *dbname;
    char *mkey;
};

/*
 * the format for HDB keytabs is:
 * HDB:[database:file:mkey]
 */

static krb5_error_code
hdb_resolve(krb5_context context, const char *name, krb5_keytab id)
{
    struct hdb_data *d;
    const char *db, *mkey;

    d = malloc(sizeof(*d));
    if(d == NULL) {
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    db = name;
    mkey = strchr(name, ':');
    if(mkey == NULL || mkey[1] == '\0') {
	if(*name == '\0')
	    d->dbname = NULL;
	else {
	    d->dbname = strdup(name);
	    if(d->dbname == NULL) {
		free(d);
		krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
		return ENOMEM;
	    }
	}
	d->mkey = NULL;
    } else {
	if((mkey - db) == 0) {
	    d->dbname = NULL;
	} else {
	    d->dbname = malloc(mkey - db + 1);
	    if(d->dbname == NULL) {
		free(d);
		krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
		return ENOMEM;
	    }
	    memmove(d->dbname, db, mkey - db);
	    d->dbname[mkey - db] = '\0';
	}
	d->mkey = strdup(mkey + 1);
	if(d->mkey == NULL) {
	    free(d->dbname);
	    free(d);
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	}
    }
    id->data = d;
    return 0;
}

static krb5_error_code
hdb_close(krb5_context context, krb5_keytab id)
{
    struct hdb_data *d = id->data;

    free(d->dbname);
    free(d->mkey);
    free(d);
    return 0;
}

static krb5_error_code
hdb_get_name(krb5_context context,
	     krb5_keytab id,
	     char *name,
	     size_t namesize)
{
    struct hdb_data *d = id->data;

    snprintf(name, namesize, "%s%s%s",
	     d->dbname ? d->dbname : "",
	     (d->dbname || d->mkey) ? ":" : "",
	     d->mkey ? d->mkey : "");
    return 0;
}

/*
 * try to figure out the database (`dbname') and master-key (`mkey')
 * that should be used for `principal'.
 */

static krb5_error_code
find_db (krb5_context context,
	 char **dbname,
	 char **mkey,
	 krb5_const_principal principal)
{
    krb5_const_realm realm = krb5_principal_get_realm(context, principal);
    krb5_error_code ret;
    struct hdb_dbinfo *head, *dbinfo = NULL;

    *dbname = *mkey = NULL;

    ret = hdb_get_dbinfo(context, &head);
    if (ret)
	return ret;

    while ((dbinfo = hdb_dbinfo_get_next(head, dbinfo)) != NULL) {
	const char *p = hdb_dbinfo_get_realm(context, dbinfo);
	if (p && strcmp (realm, p) == 0) {
	    p = hdb_dbinfo_get_dbname(context, dbinfo);
	    if (p)
		*dbname = strdup(p);
	    p = hdb_dbinfo_get_mkey_file(context, dbinfo);
	    if (p)
		*mkey = strdup(p);
	    break;
	}
    }
    hdb_free_dbinfo(context, &head);
    if (*dbname == NULL)
	*dbname = strdup(HDB_DEFAULT_DB);
    return 0;
}

/*
 * find the keytab entry in `id' for `principal, kvno, enctype' and return
 * it in `entry'.  return 0 or an error code
 */

static krb5_error_code
hdb_get_entry(krb5_context context,
	      krb5_keytab id,
	      krb5_const_principal principal,
	      krb5_kvno kvno,
	      krb5_enctype enctype,
	      krb5_keytab_entry *entry)
{
    hdb_entry_ex ent;
    krb5_error_code ret;
    struct hdb_data *d = id->data;
    const char *dbname = d->dbname;
    const char *mkey   = d->mkey;
    char *fdbname = NULL, *fmkey = NULL;
    HDB *db;
    int i;

    memset(&ent, 0, sizeof(ent));

    if (dbname == NULL) {
	ret = find_db(context, &fdbname, &fmkey, principal);
	if (ret)
	    return ret;
	dbname = fdbname;
	mkey = fmkey;
    }

    ret = hdb_create (context, &db, dbname);
    if (ret)
	goto out2;
    ret = hdb_set_master_keyfile (context, db, mkey);
    if (ret) {
	(*db->hdb_destroy)(context, db);
	goto out2;
    }
	
    ret = (*db->hdb_open)(context, db, O_RDONLY, 0);
    if (ret) {
	(*db->hdb_destroy)(context, db);
	goto out2;
    }
    ret = (*db->hdb_fetch)(context, db, principal,
			   HDB_F_DECRYPT|
			   HDB_F_GET_CLIENT|HDB_F_GET_SERVER|HDB_F_GET_KRBTGT,
			   &ent);

    if(ret == HDB_ERR_NOENTRY) {
	ret = KRB5_KT_NOTFOUND;
	goto out;
    }else if(ret)
	goto out;

    if(kvno && ent.entry.kvno != kvno) {
	hdb_free_entry(context, &ent);
 	ret = KRB5_KT_NOTFOUND;
	goto out;
    }
    if(enctype == 0)
	if(ent.entry.keys.len > 0)
	    enctype = ent.entry.keys.val[0].key.keytype;
    ret = KRB5_KT_NOTFOUND;
    for(i = 0; i < ent.entry.keys.len; i++) {
	if(ent.entry.keys.val[i].key.keytype == enctype) {
	    krb5_copy_principal(context, principal, &entry->principal);
	    entry->vno = ent.entry.kvno;
	    krb5_copy_keyblock_contents(context,
					&ent.entry.keys.val[i].key,
					&entry->keyblock);
	    ret = 0;
	    break;
	}
    }
    hdb_free_entry(context, &ent);
 out:
    (*db->hdb_close)(context, db);
    (*db->hdb_destroy)(context, db);
 out2:
    free(fdbname);
    free(fmkey);
    return ret;
}

krb5_kt_ops hdb_kt_ops = {
    "HDB",
    hdb_resolve,
    hdb_get_name,
    hdb_close,
    NULL,		/* destroy */
    hdb_get_entry,
    NULL,		/* start_seq_get */
    NULL,		/* next_entry */
    NULL,		/* end_seq_get */
    NULL,		/* add */
    NULL		/* remove */
};
