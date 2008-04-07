/*
 * Copyright (c) 2008 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#include "sqlite3.h"

RCSID("$Id$");

typedef struct krb5_scache {
    char *name;
    char *file;
    sqlite3 *db;

    int cid;

    /* */
    HEIMDAL_MUTEX imutex;
    sqlite3_stmt *icred;
    sqlite3_stmt *iprincipal;

    sqlite3_stmt *icache;
    sqlite3_stmt *ucachep;
    sqlite3_stmt *scache;


} krb5_scache;

#define	SCACHE(X)	((krb5_scache *)(X)->data.data)

#define DEFAULT_SCACHE "/tmp/scache-foo" /* XXX */

#define SCACHE_STRING(x) 	#x
#define SCACHE_XSTRING(x) 	SCACHE_STRING(x)

#define SCACHE_DEF_CID		0
#define SCACHE_DEF_CID_NAME	SCACHE_XSTRING(SCACHE_DEF_CID)

/*
 *
 */

#define SQL_CMASTER ""				\
	"CREATE TABLE master ("		\
	"version INTEGER NOT NULL,"		\
	"defaultcache INTEGER NOT NULL"		\
	")"

#define SQL_SETUP_MASTER "INSERT INTO master VALUES(1, " SCACHE_DEF_CID_NAME ")"

#define SQL_CCACHE ""				\
	"CREATE TABLE caches ("			\
	"principal TEXT,"			\
	"name TEXT NOT NULL"			\
	")"

#define SQL_ICACHE "INSERT INTO caches (name) VALUES(?)"
#define SQL_UCACHE_PRINCIPAL "UPDATE caches SET principal=? WHERE OID=?"
#define SQL_SCACHE "SELECT principal,name FROM caches WHERE OID=?"

#define SQL_CCREDS ""				\
	"CREATE TABLE credentials ("		\
	"cid INTEGER NOT NULL,"			\
	"kvno INTEGER NOT NULL,"		\
	"etype INTEGER NOT NULL,"		\
	"cred BLOB NOT NULL"			\
	")"

#define SQL_ICRED "INSERT INTO credentials (cid, kvno, etype, cred) VALUES (?,?,?,?)"

#define SQL_CPRINCIPALS ""			\
	"CREATE TABLE principals ("		\
	"principal TEXT NOT NULL,"		\
	"type INTEGER NOT NULL,"		\
	"credential_id INTEGER NOT NULL"	\
	")"

#define SQL_IPRINCIPAL "INSERT INTO principals (principal, type, credential_id) VALUES (?,?,?)"

/*
 * sqlite destructors
 */

static void
free_data(void *data)
{
    free(data);
}

static void
free_krb5(void *str)
{
    krb5_xfree(str);
}

/*
 *
 */

static const char*
scc_get_name(krb5_context context,
	     krb5_ccache id)
{
    return SCACHE(id)->name;
}

static krb5_scache *
scc_alloc(const char *name)
{
    krb5_scache *s;

    ALLOC(s, 1);
    if(s == NULL)
	return NULL;

    /* XXX resolve name */
    s->cid = SCACHE_DEF_CID;
    s->file = DEFAULT_SCACHE;
    s->name = SCACHE_DEF_CID_NAME;

    HEIMDAL_MUTEX_init(&s->imutex);

    return s;
}

static krb5_error_code
open_database(krb5_context context, krb5_scache *s, int flags)
{
    int ret;
    ret = sqlite3_open_v2(s->file, &s->db, SQLITE_OPEN_READWRITE|flags, NULL);
    if (ret) {
	if (s->db) {
	    krb5_set_error_string(context, "Error opening scache file %s: %s", 
				  s->file, sqlite3_errmsg(s->db));
	    sqlite3_close(s->db);
	    s->db = NULL;
	} else
	    krb5_set_error_string(context, "out of memory");
	return ENOENT;
    }
    return 0;
}

static krb5_error_code
make_database(krb5_context context, krb5_scache *s, int create)
{
    int ret;

    if (s->db)
	return 0;

    ret = open_database(context, s, 0);
    if (ret) {
	ret = open_database(context, s, SQLITE_OPEN_CREATE);
	if (ret)
	    return ret;

	sqlite3_exec(s->db, SQL_CMASTER, NULL, NULL, NULL);
	sqlite3_exec(s->db, SQL_CCACHE, NULL, NULL, NULL);
	ret = sqlite3_exec(s->db, SQL_CCREDS, NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
	    krb5_set_error_string(context, "Failed to create table creds: %s",
				  sqlite3_errmsg(s->db));
	    goto end;
	}
	sqlite3_exec(s->db, SQL_CPRINCIPALS, NULL, NULL, NULL);

	sqlite3_exec(s->db, SQL_SETUP_MASTER, NULL, NULL, NULL);
    }

    ret = sqlite3_prepare_v2(s->db, SQL_ICRED, -1, &s->icred, NULL);
    if (ret != SQLITE_OK) {
	krb5_set_error_string(context, "Failed to create icred: %s",
			      sqlite3_errmsg(s->db));
	goto end;
    }
    ret = sqlite3_prepare_v2(s->db, SQL_IPRINCIPAL, -1, &s->iprincipal, NULL);
    if (ret != SQLITE_OK) {
	krb5_set_error_string(context, "Failed to create iprincipal: %s",
			      sqlite3_errmsg(s->db));
	goto end;
    }

    ret = sqlite3_prepare_v2(s->db, SQL_ICACHE, -1, &s->icache, NULL);
    if (ret != SQLITE_OK) {
	krb5_set_error_string(context, "Failed to create icache: %s",
			      sqlite3_errmsg(s->db));
	goto end;
    }
    sqlite3_prepare_v2(s->db, SQL_UCACHE_PRINCIPAL, -1, &s->ucachep, NULL);
    sqlite3_prepare_v2(s->db, SQL_SCACHE, -1, &s->scache, NULL);

    if (create) {
	/* create inital entry */
	sqlite3_bind_text(s->icache, 1, s->name, -1, NULL);
	do {
	    ret = sqlite3_step(s->icache);
	} while (ret == SQLITE_ROW);
	if (ret != SQLITE_DONE) {
	    krb5_set_error_string(context, "Failed to add scache: %d", ret);
	    goto end;
	}
	sqlite3_reset(s->icred);
    }

    return 0;

end:
    if (s->db)
	sqlite3_close(s->db);
    if (create)
	unlink(s->file);

    return ENOENT;
}

static krb5_error_code
scc_resolve(krb5_context context, krb5_ccache *id, const char *res)
{
    krb5_scache *s;

    s = scc_alloc(res);
    if (s == NULL) {
	krb5_set_error_string (context, "malloc: out of memory");
	return KRB5_CC_NOMEM;
    }
    
    (*id)->data.data = s;
    (*id)->data.length = sizeof(*s);

    return 0;
}

static krb5_error_code
scc_gen_new(krb5_context context, krb5_ccache *id)
{
    krb5_scache *s;

    s = scc_alloc(NULL);

    if (s == NULL) {
	krb5_set_error_string (context, "malloc: out of memory");
	return KRB5_CC_NOMEM;
    }
    s->cid = ++foo;

    (*id)->data.data = s;
    (*id)->data.length = sizeof(*s);

    return 0;
}

static krb5_error_code
scc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal primary_principal)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    char *str;

    ret = make_database(context, s, 1);
    if (ret)
	return ret;

    ret = krb5_unparse_name(context, primary_principal, &str);
    if (ret)
	return ret;

    sqlite3_bind_text(s->ucachep, 1, str, -1, free_krb5);
    sqlite3_bind_int(s->ucachep, 2, s->cid);

    if (sqlite3_step(s->ucachep) != SQLITE_DONE)
	ret = EPERM; /* XXX */

    sqlite3_reset(s->ucachep);

    /* XXX delete all entries for this cid, trigger ? */

    return ret;
}

static krb5_error_code
scc_close(krb5_context context,
	  krb5_ccache id)
{
    krb5_data_free(&id->data);
    return 0;
}

static krb5_error_code
scc_destroy(krb5_context context,
	    krb5_ccache id)
{
    scc_close(context, id);
    return 0;
}

static krb5_error_code
encode_creds(krb5_context context, krb5_creds *creds, krb5_data *data)
{
    krb5_error_code ret;
    krb5_storage *sp;

    sp = krb5_storage_emem();
    if (sp == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = krb5_store_creds(sp, creds);
    if (ret) {
	krb5_set_error_string(context, "Failed to store credential");
	krb5_storage_free(sp);
	return ret;
    }

    ret = krb5_storage_to_data(sp, data);
    krb5_storage_free(sp);
    if (ret)
	krb5_set_error_string(context, "Failed to encode credential");
    return ret;
}

static krb5_error_code
scc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    unsigned long long credid;
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    krb5_data data;
    char *str;

    ret = make_database(context, s, 0);
    if (ret)
	return ret;

    ret = encode_creds(context, creds, &data);
    if (ret)
	return ret;

    {
	int kvno = 0;
	Ticket t;
	size_t len;

	ret = decode_Ticket(creds->ticket.data, 
			    creds->ticket.length, &t, &len);
	if (ret) {
	    krb5_set_error_string(context, "Failed to decode ticket");
	    return ret;
	}

	if(t.enc_part.kvno)
	    kvno = *t.enc_part.kvno;

	sqlite3_bind_int(s->icred, 1, kvno);
	sqlite3_bind_int(s->icred, 2, t.enc_part.etype);

	free_Ticket(&t);
    }

    sqlite3_bind_blob(s->icred, 3, data.data, data.length, free_data);

    sqlite3_exec(s->db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    if (sqlite3_step(s->icred) != SQLITE_DONE)
	goto rollback;

    sqlite3_reset(s->icred);

    credid = sqlite3_last_insert_rowid(s->db);
    
    {
	krb5_unparse_name(context, creds->server, &str);
	
	sqlite3_bind_text(s->iprincipal, 1, str, -1, free_krb5);
	sqlite3_bind_int(s->iprincipal, 2, 1);
	sqlite3_bind_int(s->iprincipal, 3, credid);
	
	if (sqlite3_step(s->icred) != SQLITE_DONE)
	    goto rollback;
	
	sqlite3_reset(s->icred);
    }

    {
	krb5_unparse_name(context, creds->client, &str);
	
	sqlite3_bind_text(s->iprincipal, 1, str, -1, free_krb5);
	sqlite3_bind_int(s->iprincipal, 2, 0);
	sqlite3_bind_int(s->iprincipal, 3, credid);
	
	if (sqlite3_step(s->icred) != SQLITE_DONE)
	    goto rollback;
	
	sqlite3_reset(s->icred);
    }

    sqlite3_exec(s->db, "END TRANSACTION", NULL, NULL, NULL);

    return 0;

rollback:

    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);

    return ret;
}

static krb5_error_code
scc_get_principal(krb5_context context,
		  krb5_ccache id,
		  krb5_principal *principal)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    const char *str;

    *principal = NULL;

    ret = make_database(context, s, 0);
    if (ret)
	return ret;

    sqlite3_bind_int(s->scache, 1, s->cid);

    if (sqlite3_step(s->scache) != SQLITE_ROW) {
	sqlite3_reset(s->scache);
	krb5_set_error_string(context, "No principal for scache %d", s->cid);
	return ENOENT;
    }
	
    if (sqlite3_column_type(s->scache, 2) == SQLITE_TEXT) {
	sqlite3_reset(s->scache);
	krb5_set_error_string(context, "Principal data of wrong type "
			      "for scache %d", s->cid);
	return ENOENT;
    }

    str = (const char *)sqlite3_column_text(s->scache, 2);
    if (str == NULL) {
	sqlite3_reset(s->scache);
	krb5_set_error_string(context, "Principal not set "
			      "for scache %d", s->cid);
	return ENOENT;
    }

    ret = krb5_parse_name(context, str, principal);

    sqlite3_reset(s->scache);

    return ret;
}

static krb5_error_code
scc_get_first (krb5_context context,
	       krb5_ccache id,
	       krb5_cc_cursor *cursor)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;

    ret = make_database(context, s, 0);
    if (ret)
	return ret;

    krb5_clear_error_string(context);
    return KRB5_CC_END;
}

static krb5_error_code
scc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    krb5_clear_error_string(context);
    return KRB5_CC_END;
}

static krb5_error_code
scc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{
    return 0;
}

static krb5_error_code
scc_remove_cred(krb5_context context,
		 krb5_ccache id,
		 krb5_flags which,
		 krb5_creds *mcreds)
{
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;

    ret = make_database(context, s, 0);
    if (ret)
	return ret;

    return 0;
}

static krb5_error_code
scc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    return 0; /* XXX */
}
		    
static krb5_error_code
scc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    krb5_clear_error_string(context);
    return KRB5_CC_END;
}

static krb5_error_code
scc_get_cache_next(krb5_context context, krb5_cc_cursor cursor, krb5_ccache *id)
{
    krb5_clear_error_string(context);
    return KRB5_CC_END;
}

static krb5_error_code
scc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    return 0;
}

static krb5_error_code
scc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_scache *sfrom = SCACHE(from);
    krb5_scache *sto = SCACHE(to);
    krb5_error_code ret;

    ret = make_database(context, sfrom, 0);
    if (ret)
	return ret;

    ret = make_database(context, sto, 1);
    if (ret)
	return ret;


    return 0;
}

static krb5_error_code
scc_default_name(krb5_context context, char **str)
{
    asprintf(str, "SCACHE:%s:%s", DEFAULT_SCACHE, SCACHE_DEF_CID_NAME);
    if (*str == NULL) {
	krb5_set_error_string(context, "out of memory");
	return ENOMEM;
    }
    return 0;
}


/**
 * Variable containing the SCACHE based credential cache implemention.
 *
 * @ingroup krb5_ccache
 */

const krb5_cc_ops krb5_scc_ops = {
    "SCACHE",
    scc_get_name,
    scc_resolve,
    scc_gen_new,
    scc_initialize,
    scc_destroy,
    scc_close,
    scc_store_cred,
    NULL, /* scc_retrieve */
    scc_get_principal,
    scc_get_first,
    scc_get_next,
    scc_end_get,
    scc_remove_cred,
    scc_set_flags,
    NULL,
    scc_get_cache_first,
    scc_get_cache_next,
    scc_end_cache_get,
    scc_move,
    scc_default_name
};
