/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * Copyright (c) 2011 - Howard Chu, Symas Corp.
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

#if HAVE_LMDB

/* LMDB */

#include <lmdb.h>

#define	KILO	1024

#define E(sym, kret) case sym: ret = kret; ename = #sym; break

/* Note: calls krb5_set_error_message() */
static krb5_error_code
mdb2krb5_code(krb5_context context, int code)
{
    krb5_error_code ret = 0;
    const char *ename = "UNKNOWN";
    const char *estr = mdb_strerror(code);

    switch (code) {
    case MDB_SUCCESS: return 0;
    E(MDB_KEYEXIST, HDB_ERR_EXISTS);
    E(MDB_NOTFOUND, HDB_ERR_NOENTRY);
    E(MDB_PAGE_NOTFOUND, HDB_ERR_UK_SERROR);
    E(MDB_CORRUPTED, HDB_ERR_UK_SERROR);
    E(MDB_PANIC, HDB_ERR_UK_SERROR);
    E(MDB_VERSION_MISMATCH, HDB_ERR_UK_SERROR);
    E(MDB_INVALID, HDB_ERR_UK_SERROR);
    E(MDB_MAP_FULL, HDB_ERR_UK_SERROR);
    E(MDB_DBS_FULL, HDB_ERR_UK_SERROR);
    E(MDB_READERS_FULL, HDB_ERR_UK_SERROR);
    E(MDB_TLS_FULL, HDB_ERR_UK_SERROR);
    E(MDB_TXN_FULL, HDB_ERR_UK_SERROR);
    E(MDB_CURSOR_FULL, HDB_ERR_UK_SERROR);
    E(MDB_PAGE_FULL, HDB_ERR_UK_SERROR);
    E(MDB_MAP_RESIZED, HDB_ERR_UK_SERROR);
    E(MDB_INCOMPATIBLE, HDB_ERR_UK_SERROR);
    E(MDB_BAD_RSLOT, HDB_ERR_UK_SERROR);
    E(MDB_BAD_TXN, HDB_ERR_UK_SERROR);
    E(MDB_BAD_VALSIZE, HDB_ERR_UK_SERROR);
    E(MDB_BAD_DBI, HDB_ERR_UK_SERROR);
    default:
        if (code > 0 && code < 100)
            ret = code;
        else
            ret = HDB_ERR_UK_SERROR;
        break;
    }
    if (ret)
        krb5_set_error_message(context, ret, "MDB error %s (%d): %s",
                               ename, code, estr);
    return ret;
}

typedef struct mdb_info {
    MDB_env *e;
    MDB_txn *t;
    MDB_dbi d;
    MDB_cursor *c;
    int oflags;
    mode_t mode;
    size_t mapsize;
    unsigned int in_tx:1;
} mdb_info;

/* See below */
struct keep_it_open {
    char *path;
    MDB_env *env;
    MDB_dbi d;
    unsigned int oflags;
    size_t refs;
    size_t mapsize;
    unsigned int valid:1;
    struct keep_it_open *next;
} *keep_them_open;
HEIMDAL_MUTEX keep_them_open_lock = HEIMDAL_MUTEX_INITIALIZER;

/*
 * On Unix LMDB uses fcntl() byte-range locks, and unlike SQLite3 (which also
 * uses fcntl() byte-range locks) LMDB takes no precautions to avoid early
 * first-close()s that cause other threads' locks to get dropped.  No, LMDB
 * requires the caller to take such precautions.  For us that means opening one
 * mdb env per-{HDB, mode} (where mode is read-write or read-only), never
 * closing it, and sharing it with all threads.
 *
 * Sharing an MDB_env * across multiple threads is documented to be safe, and
 * internally LMDB uses pread(2), pwrite(2), and mmap(2) for I/O, using
 * read(2)/write(2) only in the DB copy routines that we don't use.
 *
 * On WIN32 we don't have to do any of this, however, to avoid ifdef spaghetti,
 * we share this code on all platforms, even if it isn't strictly needed.
 *
 * Also, one must call mdb_open() (aka mdb_dbi_open()) only once per call to
 * mdb_env_open() and per B-tree.  We only use one B-tree in each LMDB: the
 * main one.
 *
 * On success this outputs an `MDB_env *' (the handle for the LMDB) and an
 * `MDB_dbi' (the handle for the main B-tree in the LMDB).
 *
 * ALSO, LMDB requires that we re-open the `MDB_env' when the database grows
 * larger than the mmap size.  We handle this by finding in `keep_them_open'
 * the env we already have, marking it unusable, and the finding some other
 * better one or opening a new one and adding it to the list.
 */
static krb5_error_code
my_mdb_env_create_and_open(krb5_context context,
                           mdb_info *mi,
                           const char *path,
                           int mapfull)
{
    struct keep_it_open *p, *n;
    MDB_txn *txn = NULL;
    unsigned int flags = MDB_NOSUBDIR | MDB_NOTLS;
    struct stat st;
    size_t mapsize = 0;
    int max_readers;
    int locked = 0;
    int code = 0;

    mi->oflags &= O_ACCMODE;
    flags |= (mi->oflags == O_RDONLY) ? MDB_RDONLY : 0;

    mi->e = NULL;

    /*
     * Allocate a new object, in case we don't already have one in
     * `keep_them_open'; if we don't need it, we'll free it.  This way we do
     * some of the work of creating one while not holding a lock.
     */
    if ((n = calloc(1, sizeof(*n))) == NULL ||
        (n->path = strdup(path)) == NULL) {
        free(n);
        return krb5_enomem(context);
    }
    n->oflags = mi->oflags;

    max_readers = krb5_config_get_int_default(context, NULL, 0, "kdc",
	"hdb-mdb-maxreaders", NULL);
    mapsize = krb5_config_get_int_default(context, NULL, 0, "kdc", "hdb-mdb-mapsize",
                                    NULL);
    if (mapsize > INT_MAX)
        mapsize = 0;

    memset(&st, 0, sizeof(st));
    if (stat(path, &st) == 0 && st.st_size > mapsize * KILO)
        mapsize += (st.st_size + (st.st_size >> 2)) / KILO;
    if (mapsize < 100 * 1024)
        mapsize = 100 * 1024; /* 100MB */
    if (mapsize < mi->mapsize)
        mapsize = mi->mapsize;
    if (mapfull)
        mapsize += 10 * 1024;
    if ((code = mdb_env_create(&n->env)) ||
        (max_readers && (code = mdb_env_set_maxreaders(n->env, max_readers))))
        goto out;

    /* Look for an existing env */
    HEIMDAL_MUTEX_lock(&keep_them_open_lock);
    locked = 1;
    for (p = keep_them_open; p; p = p->next) {
        if (strcmp(p->path, path) != 0)
            continue;
        if (p->mapsize > mapsize)
            /* Always increase mapsize */
            mapsize = p->mapsize + (p->mapsize >> 1);
        if (!p->valid || p->oflags != mi->oflags)
            continue;
        /* Found one; output it and get out */
        mi->e = p->env;
        mi->d = p->d;
        p->refs++;
        goto out;
    }

    /* Did not find one, so open and add this one to the list */

    /* Open the LMDB itself */
    n->refs = 1;
    n->valid = 1;
    krb5_debug(context, 5, "Opening HDB LMDB %s with mapsize %llu",
               path, (unsigned long long)mapsize * KILO);
    code = mdb_env_set_mapsize(n->env, mapsize * KILO);
    if (code == 0)
        code = mdb_env_open(n->env, path, flags, mi->mode);
    if (code == 0)
        /* Open a transaction so we can resolve the main B-tree */
        code = mdb_txn_begin(n->env, NULL, MDB_RDONLY, &txn);
    if (code == 0)
        /* Resolve the main B-tree */
        code = mdb_open(txn, NULL, 0, &n->d);
    if (code)
        goto out;

    /* Successfully opened the LMDB; output the two handles */
    mi->mapsize = n->mapsize = mapsize;
    mi->e = n->env;
    mi->d = n->d;

    /* Add this keep_it_open to the front of the list */
    n->next = keep_them_open;
    keep_them_open = n;
    n = NULL;

out:
    if (locked)
        HEIMDAL_MUTEX_unlock(&keep_them_open_lock);
    if (n) {
        if (n->env)
            mdb_env_close(n->env);
        free(n->path);
        free(n);
    }
    (void) mdb_txn_commit(txn); /* Safe when `txn == NULL' */
    return mdb2krb5_code(context, code);
}

static void
my_mdb_env_close(krb5_context context,
                 const char *db_name,
                 MDB_env **envp)
{
    struct keep_it_open **prev;
    struct keep_it_open *p, *old;
    size_t refs_seen = 0;
    size_t slen = strlen(db_name);
    MDB_env *env = *envp;
    
    if (env == NULL)
        return;

    HEIMDAL_MUTEX_lock(&keep_them_open_lock);
    for (p = keep_them_open; p; p = p->next) {
        /*
         * We can have multiple open ones and we need to know if this is the
         * last one, so we can't break out early.
         */
        if (p->env == env)
            refs_seen += (--(p->refs));
        else if (strncmp(db_name, p->path, slen) == 0 &&
                 strcmp(p->path + slen, ".mdb") == 0)
            refs_seen += p->refs;
    }
    krb5_debug(context, 6, "Closing HDB LMDB %s / %p; refs %llu", db_name, env,
               (unsigned long long)refs_seen);
    prev = &keep_them_open;
    for (p = keep_them_open; !refs_seen && p; ) {
        /* We're the last close */
        if (p->refs ||
            strncmp(db_name, p->path, slen) != 0 ||
            strcmp(p->path + slen, ".mdb") != 0) {

            /* Not us; this keep_it_open stays */
            prev = &p->next;
            p = p->next;
            continue;
        }

        /* Close and remove this one */
        krb5_debug(context, 6, "Closing HDB LMDB %s (mapsize was %llu)",
                   db_name, (unsigned long long)p->mapsize * KILO);
        old = p;
        *prev = (p = p->next); /* prev stays */
        mdb_env_close(old->env);
        free(old->path);
        free(old);
    }
    HEIMDAL_MUTEX_unlock(&keep_them_open_lock);
}

/*
 * This is a wrapper around my_mdb_env_create_and_open().  It may close an
 * existing MDB_env in mi->e if it's there.  If we need to reopen because the
 * MDB grew too much, then we call this.
 */
static krb5_error_code
my_reopen_mdb(krb5_context context, HDB *db, int mapfull)
{
    mdb_info *mi = (mdb_info *)db->hdb_db;
    char *fn;
    krb5_error_code ret = 0;

    /* No-op if we don't have an open one */
    my_mdb_env_close(context, db->hdb_name, &mi->e);
    if (asprintf(&fn, "%s.mdb", db->hdb_name) == -1)
	ret = krb5_enomem(context);
    if (ret == 0)
        ret = my_mdb_env_create_and_open(context, mi, fn, mapfull);
    free(fn);
    return ret;
}

static krb5_error_code
DB_close(krb5_context context, HDB *db)
{
    mdb_info *mi = (mdb_info *)db->hdb_db;

    mdb_cursor_close(mi->c);
    mdb_txn_abort(mi->t);
    my_mdb_env_close(context, db->hdb_name, &mi->e);
    mi->c = 0;
    mi->t = 0;
    mi->e = 0;
    return 0;
}

static krb5_error_code
DB_destroy(krb5_context context, HDB *db)
{
    krb5_error_code ret;

    ret = hdb_clear_master_key(context, db);
    krb5_config_free_strings(db->virtual_hostbased_princ_svcs);
    free(db->hdb_name);
    free(db->hdb_db);
    free(db);
    return ret;
}

static krb5_error_code
DB_set_sync(krb5_context context, HDB *db, int on)
{
    mdb_info *mi = (mdb_info *)db->hdb_db;

    mdb_env_set_flags(mi->e, MDB_NOSYNC, !on);
    return mdb_env_sync(mi->e, 0);
}

static krb5_error_code
DB_lock(krb5_context context, HDB *db, int operation)
{
    db->lock_count++;
    return 0;
}

static krb5_error_code
DB_unlock(krb5_context context, HDB *db)
{
    if (db->lock_count > 1) {
	db->lock_count--;
	return 0;
    }
    heim_assert(db->lock_count == 1, "HDB lock/unlock sequence does not match");
    db->lock_count--;
    return 0;
}


static krb5_error_code
DB_seq(krb5_context context, HDB *db,
       unsigned flags, hdb_entry *entry, int flag)
{
    mdb_info *mi = db->hdb_db;
    MDB_val key, value;
    krb5_data key_data, data;
    int code;

    /*
     * No need to worry about MDB_MAP_FULL when we're scanning the DB since we
     * have snapshot semantics, and any DB growth from other transactions
     * should not affect us.
     */
    key.mv_size = 0;
    value.mv_size = 0;
    code = mdb_cursor_get(mi->c, &key, &value, flag);
    if (code)
	return mdb2krb5_code(context, code);

    key_data.data = key.mv_data;
    key_data.length = key.mv_size;
    data.data = value.mv_data;
    data.length = value.mv_size;
    memset(entry, 0, sizeof(*entry));
    if (hdb_value2entry(context, &data, entry))
	return DB_seq(context, db, flags, entry, MDB_NEXT);
    if (db->hdb_master_key_set && (flags & HDB_F_DECRYPT)) {
	code = hdb_unseal_keys (context, db, entry);
	if (code)
	    hdb_free_entry (context, db, entry);
    }
    if (entry->principal == NULL) {
	entry->principal = malloc(sizeof(*entry->principal));
	if (entry->principal == NULL) {
	    hdb_free_entry (context, db, entry);
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	} else {
	    hdb_key2principal(context, &key_data, entry->principal);
	}
    }
    return 0;
}


static krb5_error_code
DB_firstkey(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
    krb5_error_code ret = 0;
    mdb_info *mi = db->hdb_db;
    int tries = 3;
    int code = 0;

    /* Always start with a fresh cursor to pick up latest DB state */

    do {
        if (mi->t)
            mdb_txn_abort(mi->t);
        mi->t = NULL;
        if (code)
            code = my_reopen_mdb(context, db, 1);
        if (code == 0)
            code = mdb_txn_begin(mi->e, NULL, MDB_RDONLY, &mi->t);
        if (code == 0)
            code = mdb_cursor_open(mi->t, mi->d, &mi->c);
        if (code == 0) {
            ret = DB_seq(context, db, flags, entry, MDB_FIRST);
            break;
        }
    } while (code == MDB_MAP_FULL && --tries > 0);

    if (code || ret) {
        mdb_txn_abort(mi->t);
        mi->t = NULL;
    }
    return ret ? ret : mdb2krb5_code(context, code);
}


static krb5_error_code
DB_nextkey(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
    return DB_seq(context, db, flags, entry, MDB_NEXT);
}

static krb5_error_code
DB_rename(krb5_context context, HDB *db, const char *new_name)
{
    int ret;
    char *old, *new;

    if (strncmp(new_name, "mdb:", sizeof("mdb:") - 1) == 0)
        new_name += sizeof("mdb:") - 1;
    else if (strncmp(new_name, "lmdb:", sizeof("lmdb:") - 1) == 0)
        new_name += sizeof("lmdb:") - 1;
    if (asprintf(&old, "%s.mdb", db->hdb_name) == -1)
		return ENOMEM;
    if (asprintf(&new, "%s.mdb", new_name) == -1) {
		free(old);
		return ENOMEM;
    }
    ret = rename(old, new);
    free(old);
    free(new);
    if(ret)
	return errno;

    free(db->hdb_name);
    db->hdb_name = strdup(new_name);
    return 0;
}

static krb5_error_code
DB__get(krb5_context context, HDB *db, krb5_data key, krb5_data *reply)
{
    mdb_info *mi = (mdb_info*)db->hdb_db;
    MDB_txn *txn = NULL;
    MDB_val k, v;
    int tries = 3;
    int code = 0;

    k.mv_data = key.data;
    k.mv_size = key.length;

    do {
        if (txn) {
            mdb_txn_abort(txn);
            txn = NULL;
        }
        if (code)
            code = my_reopen_mdb(context, db, 1);
        if (code == 0)
            code = mdb_txn_begin(mi->e, NULL, MDB_RDONLY, &txn);
        if (code == 0)
            code = mdb_get(txn, mi->d, &k, &v);
        if (code == 0)
            krb5_data_copy(reply, v.mv_data, v.mv_size);
    } while (code == MDB_MAP_FULL && --tries > 0);

    if (code)
        mdb_txn_abort(txn);
    else
        (void) mdb_txn_commit(txn); /* Empty transaction? -> commit */
    return mdb2krb5_code(context, code);
}

static krb5_error_code
DB__put(krb5_context context, HDB *db, int replace,
	krb5_data key, krb5_data value)
{
    mdb_info *mi = (mdb_info*)db->hdb_db;
    MDB_txn *txn = NULL;
    MDB_val k, v;
    int tries = 3;
    int code = 0;

    k.mv_data = key.data;
    k.mv_size = key.length;
    v.mv_data = value.data;
    v.mv_size = value.length;

    do {
        if (txn) {
            mdb_txn_abort(txn);
            txn = NULL;
        }
        if (code)
            code = my_reopen_mdb(context, db, 1);
        if (code == 0)
            code = mdb_txn_begin(mi->e, NULL, 0, &txn);
        if (code == 0)
            code = mdb_put(txn, mi->d, &k, &v, replace ? 0 : MDB_NOOVERWRITE);
        if (code == 0) {
            /*
             * No need to call mdb_env_sync(); it's done automatically if
             * MDB_NOSYNC is not set.
             */
            code = mdb_txn_commit(txn);
            txn = NULL;
        }
    } while (code == MDB_MAP_FULL && --tries > 0);
    if (txn)
        mdb_txn_abort(txn);
    return mdb2krb5_code(context, code);
}

static krb5_error_code
DB__del(krb5_context context, HDB *db, krb5_data key)
{
    mdb_info *mi = (mdb_info*)db->hdb_db;
    MDB_txn *txn = NULL;
    MDB_val k;
    int tries = 3;
    int code = 0;

    k.mv_data = key.data;
    k.mv_size = key.length;

    do {
        if (txn) {
            mdb_txn_abort(txn);
            txn = NULL;
        }
        if (code)
            code = my_reopen_mdb(context, db, 1);
        if (code == 0)
            code = mdb_txn_begin(mi->e, NULL, 0, &txn);
        if (code == 0)
            code = mdb_del(txn, mi->d, &k, NULL);
        if (code == 0) {
            /*
             * No need to call mdb_env_sync(); it's done automatically if
             * MDB_NOSYNC is not set.
             */
            code = mdb_txn_commit(txn);
            txn = NULL;
        }
    } while (code == MDB_MAP_FULL && --tries > 0);

    if (txn)
        mdb_txn_abort(txn);
    return mdb2krb5_code(context, code);
}

static krb5_error_code
DB_open(krb5_context context, HDB *db, int oflags, mode_t mode)
{
    mdb_info *mi = (mdb_info *)db->hdb_db;
    krb5_error_code ret;

    mi->e = NULL;
    mi->mode = mode;
    mi->oflags = oflags & O_ACCMODE;
    ret = my_reopen_mdb(context, db, 0);
    if (ret) {
	krb5_prepend_error_message(context, ret, "opening %s:", db->hdb_name);
	return ret;
    }

    if ((oflags & O_ACCMODE) == O_RDONLY) {
	ret = hdb_check_db_format(context, db);
        /*
         * Dubious: if the DB is not initialized, shouldn't we tell the
         * caller??
         */
        if (ret == HDB_ERR_NOENTRY)
            return 0;
    } else {
        /* hdb_init_db() calls hdb_check_db_format() */
	ret = hdb_init_db(context, db);
    }
    if (ret) {
	DB_close(context, db);
	krb5_set_error_message(context, ret, "hdb_open: failed %s database %s",
			       (oflags & O_ACCMODE) == O_RDONLY ?
			       "checking format of" : "initialize",
			       db->hdb_name);
    }

    return ret;
}

krb5_error_code
hdb_mdb_create(krb5_context context, HDB **db,
	      const char *filename)
{
    *db = calloc(1, sizeof(**db));
    if (*db == NULL) {
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }

    (*db)->hdb_db = calloc(1, sizeof(mdb_info));
    if ((*db)->hdb_db == NULL) {
	free(*db);
	*db = NULL;
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    (*db)->hdb_name = strdup(filename);
    if ((*db)->hdb_name == NULL) {
	free((*db)->hdb_db);
	free(*db);
	*db = NULL;
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    (*db)->hdb_master_key_set = 0;
    (*db)->hdb_openp = 0;
    (*db)->hdb_capability_flags = HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL;
    (*db)->hdb_open  = DB_open;
    (*db)->hdb_close = DB_close;
    (*db)->hdb_fetch_kvno = _hdb_fetch_kvno;
    (*db)->hdb_store = _hdb_store;
    (*db)->hdb_remove = _hdb_remove;
    (*db)->hdb_firstkey = DB_firstkey;
    (*db)->hdb_nextkey= DB_nextkey;
    (*db)->hdb_lock = DB_lock;
    (*db)->hdb_unlock = DB_unlock;
    (*db)->hdb_rename = DB_rename;
    (*db)->hdb__get = DB__get;
    (*db)->hdb__put = DB__put;
    (*db)->hdb__del = DB__del;
    (*db)->hdb_destroy = DB_destroy;
    (*db)->hdb_set_sync = DB_set_sync;
    return 0;
}
#endif /* HAVE_LMDB */
