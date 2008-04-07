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

    sqlite_uint64 cid;

    sqlite3_stmt *icred;
    sqlite3_stmt *dcred;
    sqlite3_stmt *iprincipal;

    sqlite3_stmt *icache;
    sqlite3_stmt *ucachen;
    sqlite3_stmt *ucachep;
    sqlite3_stmt *dcache;
    sqlite3_stmt *scache;
    sqlite3_stmt *scache_name;

} krb5_scache;

#define	SCACHE(X)	((krb5_scache *)(X)->data.data)

#define SCACHE_DEF_NAME		"Default-cache"
#define KRB5_SCACHE_DB	"/tmp/krb5scc_%{uid}"
#define KRB5_SCACHE_NAME	"SDB:"  SCACHE_DEF_NAME ":" KRB5_SCACHE_DB

#define SCACHE_INVALID_CID	((sqlite_uint64)-1)

/*
 *
 */

#define SQL_CMASTER ""				\
	"CREATE TABLE master ("			\
	"version INTEGER NOT NULL,"		\
	"defaultcache INTEGER NOT NULL"		\
	")"

#define SQL_SETUP_MASTER "INSERT INTO master VALUES(1, 1)"

#define SQL_CCACHE ""				\
	"CREATE TABLE caches ("			\
	"principal TEXT,"			\
	"name TEXT NOT NULL"			\
	")"

#define SQL_TCACHE ""						\
	"CREATE TRIGGER CacheDropCreds AFTER DELETE ON caches "	\
	"FOR EACH ROW BEGIN "					\
	"DELETE FROM credentials WHERE cid=old.oid;"		\
	"END"

#define SQL_ICACHE "INSERT INTO caches (name) VALUES(?)"
#define SQL_UCACHE_NAME "UPDATE caches SET name=? WHERE OID=?"
#define SQL_UCACHE_PRINCIPAL "UPDATE caches SET principal=? WHERE OID=?"
#define SQL_DCACHE "DELETE FROM caches WHERE OID=?"
#define SQL_SCACHE "SELECT principal,name FROM caches WHERE OID=?"
#define SQL_SCACHE_NAME "SELECT oid FROM caches WHERE NAME=?"

#define SQL_CCREDS ""				\
	"CREATE TABLE credentials ("		\
	"cid INTEGER NOT NULL,"			\
	"kvno INTEGER NOT NULL,"		\
	"etype INTEGER NOT NULL,"		\
	"cred BLOB NOT NULL"			\
	")"

#define SQL_TCRED ""							\
	"CREATE TRIGGER credDropPrincipal AFTER DELETE ON credentials "	\
	"FOR EACH ROW BEGIN "						\
	"DELETE FROM principals WHERE credential_id=old.oid;"		\
	"END"

#define SQL_ICRED "INSERT INTO credentials (cid, kvno, etype, cred) VALUES (?,?,?,?)"
#define SQL_DCRED "DELETE FROM credentials WHERE cid=?"

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

static void
scc_free(krb5_scache *s)
{
    if (s->file)
	free(s->file);
    if (s->name)
	free(s->name);

    if (s->icred)
	sqlite3_finalize(s->icred);
    if (s->dcred)
	sqlite3_finalize(s->dcred);
    if (s->iprincipal)
	sqlite3_finalize(s->iprincipal);
    if (s->icache)
	sqlite3_finalize(s->icache);
    if (s->ucachen)
	sqlite3_finalize(s->ucachen);
    if (s->ucachep)
	sqlite3_finalize(s->ucachep);
    if (s->dcache)
	sqlite3_finalize(s->dcache);
    if (s->scache)
	sqlite3_finalize(s->scache);
    if (s->scache_name)
	sqlite3_finalize(s->scache_name);

    if (s->db)
	sqlite3_close(s->db);
    free(s);
}

static krb5_scache *
scc_alloc(krb5_context context, const char *name)
{
    krb5_scache *s;

    ALLOC(s, 1);
    if(s == NULL)
	return NULL;

    s->cid = SCACHE_INVALID_CID;

    if (name) {
	char *file;

	if (*name == '\0') {
	    /* XXX get default cid */
	    name = SCACHE_DEF_NAME;
	}
	s->name = strdup(name);
	file = strchr(s->name, ':');
	if (file) {
	    *file++ = '\0';
	    s->file = strdup(file);
	} else {
	    _krb5_expand_default_cc_name(context, KRB5_SCACHE_DB, &s->file);
	}
    } else {
	_krb5_expand_default_cc_name(context, KRB5_SCACHE_DB, &s->file);
	asprintf(&s->name, "unique:%08x", (unsigned long)s);
    }
    if (s->file == NULL || s->name == NULL) {
	scc_free(s);
	return NULL;
    }

    return s;
}

static krb5_error_code
default_db(krb5_context context, sqlite3 **db)
{
    char *name;
    int ret;

    ret = _krb5_expand_default_cc_name(context, KRB5_SCACHE_DB, &name);
    if (ret)
	return ret;

    ret = sqlite3_open_v2(name, db, SQLITE_OPEN_READWRITE, NULL);
    free(name);
    if (ret != SQLITE_OK) {
	krb5_clear_error_string(context);
	return ENOENT;
    }
	
    return 0;
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
prepare_stmt(krb5_context context, sqlite3 *db, sqlite3_stmt **stmt, const char *str)
{
    int ret;

    ret = sqlite3_prepare_v2(db, str, -1, stmt, NULL);
    if (ret != SQLITE_OK) {
	krb5_set_error_string(context, "Failed to prepare stmt %s: %s", 
			      str, sqlite3_errmsg(db));
	return ENOENT;
    }
    return 0;
}

static krb5_error_code
exec_stmt(krb5_context context, sqlite3 *db, const char *str,
	  krb5_error_code code)
{
    int ret;
    
    ret = sqlite3_exec(db, str, NULL, NULL, NULL);
    if (ret != SQLITE_OK) {
	krb5_set_error_string(context, "Execute %s: %s", str,
			      sqlite3_errmsg(db));
	return code;
    }
    return 0;
}

static krb5_error_code
create_cache(krb5_context context, krb5_scache *s)
{
    int ret;

    sqlite3_bind_text(s->icache, 1, s->name, -1, NULL);
    do {
	ret = sqlite3_step(s->icache);
    } while (ret == SQLITE_ROW);
    if (ret != SQLITE_DONE) {
	krb5_set_error_string(context, "Failed to add scache: %d", ret);
	return KRB5_CC_IO;
    }
    sqlite3_reset(s->icache);
    
    s->cid = sqlite3_last_insert_rowid(s->db);

    return 0;
}

#ifdef TRACEME
static void
trace(void* ptr, const char * str)
{
    printf("SQL: %s\n", str);
}
#endif

static krb5_error_code
make_database(krb5_context context, krb5_scache *s)
{
    int created_file = 0;
    int ret;

    if (s->db)
	return 0;

    ret = open_database(context, s, 0);
    if (ret) {
	ret = open_database(context, s, SQLITE_OPEN_CREATE);
	if (ret) goto out;

	created_file = 1;

	ret = exec_stmt(context, s->db, SQL_CMASTER, KRB5_CC_IO);
	if (ret) goto out;
	ret = exec_stmt(context, s->db, SQL_CCACHE, KRB5_CC_IO);
	if (ret) goto out;
	ret = exec_stmt(context, s->db, SQL_CCREDS, KRB5_CC_IO);
	if (ret) goto out;
	ret = exec_stmt(context, s->db, SQL_CPRINCIPALS, KRB5_CC_IO);
	if (ret) goto out;
	ret = exec_stmt(context, s->db, SQL_SETUP_MASTER, KRB5_CC_IO);
	if (ret) goto out;

	ret = exec_stmt(context, s->db, SQL_TCACHE, KRB5_CC_IO);
	if (ret) goto out;
	ret = exec_stmt(context, s->db, SQL_TCRED, KRB5_CC_IO);
	if (ret) goto out;
    }

#ifdef TRACEME
    sqlite3_trace(s->db, trace, NULL);
#endif

    ret = prepare_stmt(context, s->db, &s->icred, SQL_ICRED);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->dcred, SQL_DCRED);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->iprincipal, SQL_IPRINCIPAL);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->icache, SQL_ICACHE);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->ucachen, SQL_UCACHE_NAME);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->ucachep, SQL_UCACHE_PRINCIPAL);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->dcache, SQL_DCACHE);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->scache, SQL_SCACHE);
    if (ret) goto out;
    ret = prepare_stmt(context, s->db, &s->scache_name, SQL_SCACHE_NAME);
    if (ret) goto out;

    return 0;

out:
    if (s->db)
	sqlite3_close(s->db);
    if (created_file)
	unlink(s->file);

    return ret;
}

static krb5_error_code
bind_principal(krb5_context context, 
	       sqlite3 *db,
	       sqlite3_stmt *stmt,
	       int col,
	       krb5_const_principal principal)
{
    krb5_error_code ret;
    char *str;

    ret = krb5_unparse_name(context, principal, &str);
    if (ret)
	return ret;

    ret = sqlite3_bind_text(stmt, col, str, -1, free_krb5);
    if (ret != SQLITE_OK) {
	krb5_xfree(str);
	krb5_set_error_string(context, "bind principal: %s",
			      sqlite3_errmsg(db));
	return ENOMEM;
    }
    return 0;
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

static krb5_error_code
scc_resolve(krb5_context context, krb5_ccache *id, const char *res)
{
    krb5_scache *s;
    int ret;

    s = scc_alloc(context, res);
    if (s == NULL) {
	krb5_set_error_string (context, "malloc: out of memory");
	return KRB5_CC_NOMEM;
    }

    ret = make_database(context, s);
    if (ret) {
	scc_free(s);
	return ret;
    }

    ret = sqlite3_bind_text(s->scache_name, 1, s->name, -1, NULL);
    if (ret != SQLITE_OK) {
	krb5_set_error_string(context, "bind name: %s", sqlite3_errmsg(s->db));
	scc_free(s);
	return ENOMEM;
    }

    if (sqlite3_step(s->scache_name) == SQLITE_ROW) {

	if (sqlite3_column_type(s->scache_name, 0) != SQLITE_INTEGER) {
	    sqlite3_reset(s->scache);
	    krb5_set_error_string(context, "Cache name of wrong type "
				  "for scache %ld", 
				  (unsigned long)s->name);
	    return KRB5_CC_END;
	}

	s->cid = sqlite3_column_int(s->scache_name, 0);
    } else {
	s->cid = SCACHE_INVALID_CID;
    }
    sqlite3_reset(s->scache);
    
    (*id)->data.data = s;
    (*id)->data.length = sizeof(*s);

    return 0;
}

static krb5_error_code
scc_gen_new(krb5_context context, krb5_ccache *id)
{
    krb5_scache *s;

    s = scc_alloc(context, NULL);

    if (s == NULL) {
	krb5_set_error_string (context, "malloc: out of memory");
	return KRB5_CC_NOMEM;
    }

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

    ret = make_database(context, s);
    if (ret)
	return ret;

    sqlite3_exec(s->db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    if (s->cid == SCACHE_INVALID_CID) {
	ret = create_cache(context, s);
	if (ret)
	    goto rollback;
    } else {
	sqlite3_bind_int(s->dcred, 1, s->cid);
	do {
	    ret = sqlite3_step(s->dcred);
	} while (ret == SQLITE_ROW);
	sqlite3_reset(s->dcred);
	if (ret != SQLITE_DONE) {
	    krb5_set_error_string(context, "Failed to delete old "
				  "credentials: %s", sqlite3_errmsg(s->db));
	    ret = KRB5_CC_IO;
	    goto rollback;
	}
    }

    ret = bind_principal(context, s->db, s->ucachep, 1, primary_principal);
    if (ret)
	goto rollback;
    sqlite3_bind_int(s->ucachep, 2, s->cid);

    do {
	ret = sqlite3_step(s->ucachep);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->ucachep);
    if (ret != SQLITE_DONE) {
	krb5_set_error_string(context, "Failed to bind principal to cache %s",
			      sqlite3_errmsg(s->db));
	ret = KRB5_CC_IO;
	goto rollback;
    }

    sqlite3_exec(s->db, "END TRANSACTION", NULL, NULL, NULL);

    return 0;

rollback:
    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);

    return ret;

}

static krb5_error_code
scc_close(krb5_context context,
	  krb5_ccache id)
{
    scc_free(SCACHE(id));
    return 0;
}

static krb5_error_code
scc_destroy(krb5_context context,
	    krb5_ccache id)
{
    krb5_scache *s = SCACHE(id);
    int ret;

    if (s->cid == SCACHE_INVALID_CID)
	return 0;

    sqlite3_bind_int(s->dcache, 1, s->cid);
    do {
	ret = sqlite3_step(s->dcache);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->dcache);
    if (ret != SQLITE_DONE) {
	krb5_set_error_string(context, "Failed to destroy cache %s: %s",
			      s->name, sqlite3_errmsg(s->db));
	return KRB5_CC_IO;
    }
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
decode_creds(krb5_context context, const void *data, size_t length,
	     krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_storage *sp;

    sp = krb5_storage_from_readonly_mem(data, length);
    if (sp == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = krb5_ret_creds(sp, creds);
    krb5_storage_free(sp);
    if (ret) {
	krb5_set_error_string(context, "Failed to read credential");
	return ret;
    }
    return 0;
}


static krb5_error_code
scc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    sqlite_uint64 credid;
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;
    krb5_data data;

    ret = make_database(context, s);
    if (ret)
	return ret;

    ret = encode_creds(context, creds, &data);
    if (ret)
	return ret;

    sqlite3_bind_int(s->icred, 1, s->cid);
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

	sqlite3_bind_int(s->icred, 2, kvno);
	sqlite3_bind_int(s->icred, 3, t.enc_part.etype);

	free_Ticket(&t);
    }

    sqlite3_bind_blob(s->icred, 4, data.data, data.length, free_data);

    sqlite3_exec(s->db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    do {
	ret = sqlite3_step(s->icred);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(s->icred);
    if (ret != SQLITE_DONE) {
	krb5_set_error_string(context, "Failed to add credential: %s", 
			      sqlite3_errmsg(s->db));
	goto rollback;
    }

    credid = sqlite3_last_insert_rowid(s->db);
    
    {
	bind_principal(context, s->db, s->iprincipal, 1, creds->server);
	sqlite3_bind_int(s->iprincipal, 2, 1);
	sqlite3_bind_int(s->iprincipal, 3, credid);
	
	do {
	    ret = sqlite3_step(s->iprincipal);
	} while (ret == SQLITE_ROW);
	sqlite3_reset(s->iprincipal);
	if (ret != SQLITE_DONE) {
	    krb5_set_error_string(context, "Failed to add principal: %s", 
				  sqlite3_errmsg(s->db));
	    goto rollback;
	}
    }

    {
	bind_principal(context, s->db, s->iprincipal, 1, creds->client);
	sqlite3_bind_int(s->iprincipal, 2, 0);
	sqlite3_bind_int(s->iprincipal, 3, credid);
	
	do {
	    ret = sqlite3_step(s->iprincipal);
	} while (ret == SQLITE_ROW);
	sqlite3_reset(s->iprincipal);
	if (ret != SQLITE_DONE) {
	    krb5_set_error_string(context, "Failed to add principal: %s", 
				  sqlite3_errmsg(s->db));
	    goto rollback;
	}
    }

    sqlite3_exec(s->db, "END TRANSACTION", NULL, NULL, NULL);

    return 0;

rollback:
    krb5_set_error_string(context, "store credentials: %s", sqlite3_errmsg(s->db));
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

    ret = make_database(context, s);
    if (ret)
	return ret;

    sqlite3_bind_int(s->scache, 1, s->cid);

    if (sqlite3_step(s->scache) != SQLITE_ROW) {
	sqlite3_reset(s->scache);
	krb5_set_error_string(context, "No principal for cache SCACHE:%s:%s", 
			      s->name, s->file);
	return KRB5_CC_END;
    }
	
    if (sqlite3_column_type(s->scache, 0) != SQLITE_TEXT) {
	sqlite3_reset(s->scache);
	krb5_set_error_string(context, "Principal data of wrong type "
			      "for SCACHE:%s:%s", 
			      s->name, s->file);
	return KRB5_CC_END;
    }

    str = (const char *)sqlite3_column_text(s->scache, 0);
    if (str == NULL) {
	sqlite3_reset(s->scache);
	krb5_set_error_string(context, "Principal not set "
			      "for SCACHE:%s:%s", 
			      s->name, s->file);
	return KRB5_CC_END;
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
    sqlite3_stmt *stmt;

    *cursor = NULL;

    ret = make_database(context, s);
    if (ret)
	return ret;

    if (s->cid == SCACHE_INVALID_CID)
	return KRB5_CC_END;

    ret = prepare_stmt(context, s->db, &stmt, 
		       "SELECT cred FROM credentials WHERE cid = ?");
    if (ret)
	return ret;

    ret = sqlite3_bind_int(stmt, 1, s->cid);
    if (ret) {
	sqlite3_finalize(stmt);
	krb5_clear_error_string(context);
	return KRB5_CC_END;
    }
    *cursor = stmt;

    return 0;
}

static krb5_error_code
scc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    sqlite3_stmt *stmt = *cursor;
    krb5_scache *s = SCACHE(id);
    krb5_error_code ret;

    const void *data = NULL;
    size_t len = 0;

    ret = sqlite3_step(stmt);
    if (ret == SQLITE_DONE) {
	krb5_clear_error_string(context);
        return KRB5_CC_END;
    } else if (ret != SQLITE_ROW) {
	krb5_set_error_string(context, "Database failed: %s", 
			      sqlite3_errmsg(s->db));
        return KRB5_CC_IO;
    }

    if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB) {
	krb5_set_error_string(context, "credential of wrong type "
			      "for SCACHE:%s:%s", 
			      s->name, s->file);
	return KRB5_CC_END;
    }

    data = sqlite3_column_blob(stmt, 0);
    len = sqlite3_column_bytes(stmt, 0);

    ret = decode_creds(context, data, len, creds);

    krb5_clear_error_string(context);
    return ret;
}

static krb5_error_code
scc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{
    sqlite3_finalize((sqlite3_stmt *)*cursor);
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

    ret = make_database(context, s);
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
		    
struct cache_iter {
    sqlite3 *db;
    sqlite3_stmt *stmt;
};

static krb5_error_code
scc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    struct cache_iter *ctx;
    krb5_error_code ret;

    *cursor = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = default_db(context, &ctx->db);
    if (ctx->db == NULL) {
	free(ctx);
	return ret;
    }

    ret = prepare_stmt(context, ctx->db, &ctx->stmt,"SELECT name FROM caches");
    if (ret) {
	sqlite3_close(ctx->db);
	free(ctx);
	return ret;
    }

    *cursor = ctx;

    return 0;
}

static krb5_error_code
scc_get_cache_next(krb5_context context, krb5_cc_cursor cursor, krb5_ccache *id)
{
    struct cache_iter *ctx = cursor;
    krb5_error_code ret;
    const char *name;
    krb5_scache *s = NULL;

again:
    ret = sqlite3_step(ctx->stmt);
    if (ret == SQLITE_DONE) {
	krb5_clear_error_string(context);
        return KRB5_CC_END;
    } else if (ret != SQLITE_ROW) {
	krb5_set_error_string(context, "Database failed: %s", 
			      sqlite3_errmsg(s->db));
        return KRB5_CC_IO;
    }

    if (sqlite3_column_type(ctx->stmt, 0) != SQLITE_TEXT)
	goto again;

    name = (const char *)sqlite3_column_text(ctx->stmt, 0);
    if (name == NULL)
	goto again;

    ret = _krb5_cc_allocate(context, &krb5_scc_ops, id);
    if (ret)
	return ret;

    return scc_resolve(context, id, name);
}

static krb5_error_code
scc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    struct cache_iter *ctx = cursor;

    sqlite3_finalize(ctx->stmt);
    sqlite3_close(ctx->db);
    free(ctx);
    return 0;
}

static krb5_error_code
scc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_scache *sfrom = SCACHE(from);
    krb5_scache *sto = SCACHE(to);
    krb5_error_code ret;

    if (strcmp(sfrom->file, sto->file) != 0) {
	krb5_set_error_string(context, "Can't handle cross database "
			      "credential move: %s -> %s", 
			      sfrom->file, sto->file);
	return KRB5_CC_BADNAME;
    }

    ret = make_database(context, sfrom);
    if (ret)
	return ret;

    sqlite3_exec(sfrom->db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    if (sto->cid != SCACHE_INVALID_CID) {
	/* drop old cache entry */
	
	sqlite3_bind_int(sfrom->dcache, 1, sto->cid);
	do {
	    ret = sqlite3_step(sfrom->dcache);
	} while (ret == SQLITE_ROW);
	sqlite3_reset(sfrom->dcache);
	if (ret != SQLITE_DONE) {
	    krb5_set_error_string(context, "Failed to delete old cache: %d", ret);
	    goto rollback;
	}
    }

    sqlite3_bind_text(sfrom->ucachen, 1, sto->name, -1, NULL);
    sqlite3_bind_int(sfrom->ucachen, 2, sfrom->cid);

    do {
	ret = sqlite3_step(sfrom->ucachen);
    } while (ret == SQLITE_ROW);
    sqlite3_reset(sfrom->ucachen);
    if (ret != SQLITE_DONE) {
	krb5_set_error_string(context, "Failed to update new cache: %d", ret);
	goto rollback;
    }

    sto->cid = sfrom->cid;

    sqlite3_exec(sfrom->db, "END TRANSACTION", NULL, NULL, NULL);

    /* free sfrom */

    return 0;

rollback:

    sqlite3_exec(sfrom->db, "ROLLBACK", NULL, NULL, NULL);

    return KRB5_CC_IO;
}

static krb5_error_code
scc_default_name(krb5_context context, char **str)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    const char *name;
    int ret;

    ret = default_db(context, &db);
    if (ret)
	return ret;

    ret = prepare_stmt(context, db, &stmt,
		       "SELECT caches.name "
		       "FROM caches,master "
		       "WHERE master.version = 1 AND master.defaultcache = caches.oid");
    if (ret) {
	sqlite3_close(db);
	return ret;
    }

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_ROW)
	goto defaultname;

    if (sqlite3_column_type(stmt, 0) != SQLITE_TEXT)
	goto defaultname;

    name = (const char *)sqlite3_column_text(stmt, 0);
    if (name == NULL)
	goto defaultname;


    asprintf(str, "SDB:%s", name);
    if (*str == NULL)
	goto defaultname;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;

defaultname:
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return _krb5_expand_default_cc_name(context, KRB5_SCACHE_NAME, str);
}


/**
 * Variable containing the SDB based credential cache implemention.
 *
 * @ingroup krb5_ccache
 */

const krb5_cc_ops krb5_scc_ops = {
    "SDB",
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
