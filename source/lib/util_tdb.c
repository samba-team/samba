/* 
   Unix SMB/CIFS implementation.
   tdb utility functions
   Copyright (C) Andrew Tridgell   1992-1998
   Copyright (C) Rafal Szczesniak  2002
   Copyright (C) Michael Adam      2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#undef malloc
#undef realloc
#undef calloc
#undef strdup

/* these are little tdb utility functions that are meant to make
   dealing with a tdb database a little less cumbersome in Samba */

static SIG_ATOMIC_T gotalarm;

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig(void)
{
	gotalarm = 1;
}

/***************************************************************
 Make a TDB_DATA and keep the const warning in one place
****************************************************************/

TDB_DATA make_tdb_data(const uint8 *dptr, size_t dsize)
{
	TDB_DATA ret;
	ret.dptr = CONST_DISCARD(uint8 *, dptr);
	ret.dsize = dsize;
	return ret;
}

TDB_DATA string_tdb_data(const char *string)
{
	return make_tdb_data((const uint8 *)string, string ? strlen(string) : 0 );
}

TDB_DATA string_term_tdb_data(const char *string)
{
	return make_tdb_data((const uint8 *)string, string ? strlen(string) + 1 : 0);
}

/****************************************************************************
 Lock a chain with timeout (in seconds).
****************************************************************************/

static int tdb_chainlock_with_timeout_internal( TDB_CONTEXT *tdb, TDB_DATA key, unsigned int timeout, int rw_type)
{
	/* Allow tdb_chainlock to be interrupted by an alarm. */
	int ret;
	gotalarm = 0;

	if (timeout) {
		CatchSignal(SIGALRM, SIGNAL_CAST gotalarm_sig);
		tdb_setalarm_sigptr(tdb, &gotalarm);
		alarm(timeout);
	}

	if (rw_type == F_RDLCK)
		ret = tdb_chainlock_read(tdb, key);
	else
		ret = tdb_chainlock(tdb, key);

	if (timeout) {
		alarm(0);
		tdb_setalarm_sigptr(tdb, NULL);
		CatchSignal(SIGALRM, SIGNAL_CAST SIG_IGN);
		if (gotalarm && (ret == -1)) {
			DEBUG(0,("tdb_chainlock_with_timeout_internal: alarm (%u) timed out for key %s in tdb %s\n",
				timeout, key.dptr, tdb_name(tdb)));
			/* TODO: If we time out waiting for a lock, it might
			 * be nice to use F_GETLK to get the pid of the
			 * process currently holding the lock and print that
			 * as part of the debugging message. -- mbp */
			return -1;
		}
	}

	return ret;
}

/****************************************************************************
 Write lock a chain. Return -1 if timeout or lock failed.
****************************************************************************/

int tdb_chainlock_with_timeout( TDB_CONTEXT *tdb, TDB_DATA key, unsigned int timeout)
{
	return tdb_chainlock_with_timeout_internal(tdb, key, timeout, F_WRLCK);
}

/****************************************************************************
 Lock a chain by string. Return -1 if timeout or lock failed.
****************************************************************************/

int tdb_lock_bystring(TDB_CONTEXT *tdb, const char *keyval)
{
	TDB_DATA key = string_term_tdb_data(keyval);
	
	return tdb_chainlock(tdb, key);
}

int tdb_lock_bystring_with_timeout(TDB_CONTEXT *tdb, const char *keyval,
				   int timeout)
{
	TDB_DATA key = string_term_tdb_data(keyval);
	
	return tdb_chainlock_with_timeout(tdb, key, timeout);
}

/****************************************************************************
 Unlock a chain by string.
****************************************************************************/

void tdb_unlock_bystring(TDB_CONTEXT *tdb, const char *keyval)
{
	TDB_DATA key = string_term_tdb_data(keyval);

	tdb_chainunlock(tdb, key);
}

/****************************************************************************
 Read lock a chain by string. Return -1 if timeout or lock failed.
****************************************************************************/

int tdb_read_lock_bystring_with_timeout(TDB_CONTEXT *tdb, const char *keyval, unsigned int timeout)
{
	TDB_DATA key = string_term_tdb_data(keyval);
	
	return tdb_chainlock_with_timeout_internal(tdb, key, timeout, F_RDLCK);
}

/****************************************************************************
 Read unlock a chain by string.
****************************************************************************/

void tdb_read_unlock_bystring(TDB_CONTEXT *tdb, const char *keyval)
{
	TDB_DATA key = string_term_tdb_data(keyval);
	
	tdb_chainunlock_read(tdb, key);
}


/****************************************************************************
 Fetch a int32 value by a arbitrary blob key, return -1 if not found.
 Output is int32 in native byte order.
****************************************************************************/

int32 tdb_fetch_int32_byblob(TDB_CONTEXT *tdb, TDB_DATA key)
{
	TDB_DATA data;
	int32 ret;

	data = tdb_fetch(tdb, key);
	if (!data.dptr || data.dsize != sizeof(int32)) {
		SAFE_FREE(data.dptr);
		return -1;
	}

	ret = IVAL(data.dptr,0);
	SAFE_FREE(data.dptr);
	return ret;
}

/****************************************************************************
 Fetch a int32 value by string key, return -1 if not found.
 Output is int32 in native byte order.
****************************************************************************/

int32 tdb_fetch_int32(TDB_CONTEXT *tdb, const char *keystr)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_fetch_int32_byblob(tdb, key);
}

/****************************************************************************
 Store a int32 value by an arbitary blob key, return 0 on success, -1 on failure.
 Input is int32 in native byte order. Output in tdb is in little-endian.
****************************************************************************/

int tdb_store_int32_byblob(TDB_CONTEXT *tdb, TDB_DATA key, int32 v)
{
	TDB_DATA data;
	int32 v_store;

	SIVAL(&v_store,0,v);
	data.dptr = (uint8 *)&v_store;
	data.dsize = sizeof(int32);

	return tdb_store(tdb, key, data, TDB_REPLACE);
}

/****************************************************************************
 Store a int32 value by string key, return 0 on success, -1 on failure.
 Input is int32 in native byte order. Output in tdb is in little-endian.
****************************************************************************/

int tdb_store_int32(TDB_CONTEXT *tdb, const char *keystr, int32 v)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_store_int32_byblob(tdb, key, v);
}

/****************************************************************************
 Fetch a uint32 value by a arbitrary blob key, return -1 if not found.
 Output is uint32 in native byte order.
****************************************************************************/

bool tdb_fetch_uint32_byblob(TDB_CONTEXT *tdb, TDB_DATA key, uint32 *value)
{
	TDB_DATA data;

	data = tdb_fetch(tdb, key);
	if (!data.dptr || data.dsize != sizeof(uint32)) {
		SAFE_FREE(data.dptr);
		return False;
	}

	*value = IVAL(data.dptr,0);
	SAFE_FREE(data.dptr);
	return True;
}

/****************************************************************************
 Fetch a uint32 value by string key, return -1 if not found.
 Output is uint32 in native byte order.
****************************************************************************/

bool tdb_fetch_uint32(TDB_CONTEXT *tdb, const char *keystr, uint32 *value)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_fetch_uint32_byblob(tdb, key, value);
}

/****************************************************************************
 Store a uint32 value by an arbitary blob key, return 0 on success, -1 on failure.
 Input is uint32 in native byte order. Output in tdb is in little-endian.
****************************************************************************/

bool tdb_store_uint32_byblob(TDB_CONTEXT *tdb, TDB_DATA key, uint32 value)
{
	TDB_DATA data;
	uint32 v_store;
	bool ret = True;

	SIVAL(&v_store, 0, value);
	data.dptr = (uint8 *)&v_store;
	data.dsize = sizeof(uint32);

	if (tdb_store(tdb, key, data, TDB_REPLACE) == -1)
		ret = False;

	return ret;
}

/****************************************************************************
 Store a uint32 value by string key, return 0 on success, -1 on failure.
 Input is uint32 in native byte order. Output in tdb is in little-endian.
****************************************************************************/

bool tdb_store_uint32(TDB_CONTEXT *tdb, const char *keystr, uint32 value)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_store_uint32_byblob(tdb, key, value);
}
/****************************************************************************
 Store a buffer by a null terminated string key.  Return 0 on success, -1
 on failure.
****************************************************************************/

int tdb_store_bystring(TDB_CONTEXT *tdb, const char *keystr, TDB_DATA data, int flags)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_store(tdb, key, data, flags);
}

int tdb_trans_store_bystring(TDB_CONTEXT *tdb, const char *keystr,
			     TDB_DATA data, int flags)
{
	TDB_DATA key = string_term_tdb_data(keystr);
	
	return tdb_trans_store(tdb, key, data, flags);
}

/****************************************************************************
 Fetch a buffer using a null terminated string key.  Don't forget to call
 free() on the result dptr.
****************************************************************************/

TDB_DATA tdb_fetch_bystring(TDB_CONTEXT *tdb, const char *keystr)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_fetch(tdb, key);
}

/****************************************************************************
 Delete an entry using a null terminated string key. 
****************************************************************************/

int tdb_delete_bystring(TDB_CONTEXT *tdb, const char *keystr)
{
	TDB_DATA key = string_term_tdb_data(keystr);

	return tdb_delete(tdb, key);
}

/****************************************************************************
 Atomic integer change. Returns old value. To create, set initial value in *oldval. 
****************************************************************************/

int32 tdb_change_int32_atomic(TDB_CONTEXT *tdb, const char *keystr, int32 *oldval, int32 change_val)
{
	int32 val;
	int32 ret = -1;

	if (tdb_lock_bystring(tdb, keystr) == -1)
		return -1;

	if ((val = tdb_fetch_int32(tdb, keystr)) == -1) {
		/* The lookup failed */
		if (tdb_error(tdb) != TDB_ERR_NOEXIST) {
			/* but not because it didn't exist */
			goto err_out;
		}
		
		/* Start with 'old' value */
		val = *oldval;

	} else {
		/* It worked, set return value (oldval) to tdb data */
		*oldval = val;
	}

	/* Increment value for storage and return next time */
	val += change_val;
		
	if (tdb_store_int32(tdb, keystr, val) == -1)
		goto err_out;

	ret = 0;

  err_out:

	tdb_unlock_bystring(tdb, keystr);
	return ret;
}

/****************************************************************************
 Atomic unsigned integer change. Returns old value. To create, set initial value in *oldval. 
****************************************************************************/

bool tdb_change_uint32_atomic(TDB_CONTEXT *tdb, const char *keystr, uint32 *oldval, uint32 change_val)
{
	uint32 val;
	bool ret = False;

	if (tdb_lock_bystring(tdb, keystr) == -1)
		return False;

	if (!tdb_fetch_uint32(tdb, keystr, &val)) {
		/* It failed */
		if (tdb_error(tdb) != TDB_ERR_NOEXIST) { 
			/* and not because it didn't exist */
			goto err_out;
		}

		/* Start with 'old' value */
		val = *oldval;

	} else {
		/* it worked, set return value (oldval) to tdb data */
		*oldval = val;

	}

	/* get a new value to store */
	val += change_val;
		
	if (!tdb_store_uint32(tdb, keystr, val))
		goto err_out;

	ret = True;

  err_out:

	tdb_unlock_bystring(tdb, keystr);
	return ret;
}

/****************************************************************************
 Useful pair of routines for packing/unpacking data consisting of
 integers and strings.
****************************************************************************/

static size_t tdb_pack_va(uint8 *buf, int bufsize, const char *fmt, va_list ap)
{
	uint8 bt;
	uint16 w;
	uint32 d;
	int i;
	void *p;
	int len;
	char *s;
	char c;
	uint8 *buf0 = buf;
	const char *fmt0 = fmt;
	int bufsize0 = bufsize;

	while (*fmt) {
		switch ((c = *fmt++)) {
		case 'b': /* unsigned 8-bit integer */
			len = 1;
			bt = (uint8)va_arg(ap, int);
			if (bufsize && bufsize >= len)
				SSVAL(buf, 0, bt);
			break;
		case 'w': /* unsigned 16-bit integer */
			len = 2;
			w = (uint16)va_arg(ap, int);
			if (bufsize && bufsize >= len)
				SSVAL(buf, 0, w);
			break;
		case 'd': /* signed 32-bit integer (standard int in most systems) */
			len = 4;
			d = va_arg(ap, uint32);
			if (bufsize && bufsize >= len)
				SIVAL(buf, 0, d);
			break;
		case 'p': /* pointer */
			len = 4;
			p = va_arg(ap, void *);
			d = p?1:0;
			if (bufsize && bufsize >= len)
				SIVAL(buf, 0, d);
			break;
		case 'P': /* null-terminated string */
			s = va_arg(ap,char *);
			w = strlen(s);
			len = w + 1;
			if (bufsize && bufsize >= len)
				memcpy(buf, s, len);
			break;
		case 'f': /* null-terminated string */
			s = va_arg(ap,char *);
			w = strlen(s);
			len = w + 1;
			if (bufsize && bufsize >= len)
				memcpy(buf, s, len);
			break;
		case 'B': /* fixed-length string */
			i = va_arg(ap, int);
			s = va_arg(ap, char *);
			len = 4+i;
			if (bufsize && bufsize >= len) {
				SIVAL(buf, 0, i);
				memcpy(buf+4, s, i);
			}
			break;
		default:
			DEBUG(0,("Unknown tdb_pack format %c in %s\n", 
				 c, fmt));
			len = 0;
			break;
		}

		buf += len;
		if (bufsize)
			bufsize -= len;
		if (bufsize < 0)
			bufsize = 0;
	}

	DEBUG(18,("tdb_pack_va(%s, %d) -> %d\n", 
		 fmt0, bufsize0, (int)PTR_DIFF(buf, buf0)));
	
	return PTR_DIFF(buf, buf0);
}

size_t tdb_pack(uint8 *buf, int bufsize, const char *fmt, ...)
{
	va_list ap;
	size_t result;

	va_start(ap, fmt);
	result = tdb_pack_va(buf, bufsize, fmt, ap);
	va_end(ap);
	return result;
}

bool tdb_pack_append(TALLOC_CTX *mem_ctx, uint8 **buf, size_t *len,
		     const char *fmt, ...)
{
	va_list ap;
	size_t len1, len2;

	va_start(ap, fmt);
	len1 = tdb_pack_va(NULL, 0, fmt, ap);
	va_end(ap);

	if (mem_ctx != NULL) {
		*buf = TALLOC_REALLOC_ARRAY(mem_ctx, *buf, uint8,
					    (*len) + len1);
	} else {
		*buf = SMB_REALLOC_ARRAY(*buf, uint8, (*len) + len1);
	}

	if (*buf == NULL) {
		return False;
	}

	va_start(ap, fmt);
	len2 = tdb_pack_va((*buf)+(*len), len1, fmt, ap);
	va_end(ap);

	if (len1 != len2) {
		return False;
	}

	*len += len2;

	return True;
}

/****************************************************************************
 Useful pair of routines for packing/unpacking data consisting of
 integers and strings.
****************************************************************************/

int tdb_unpack(const uint8 *buf, int bufsize, const char *fmt, ...)
{
	va_list ap;
	uint8 *bt;
	uint16 *w;
	uint32 *d;
	int len;
	int *i;
	void **p;
	char *s, **b, **ps;
	char c;
	const uint8 *buf0 = buf;
	const char *fmt0 = fmt;
	int bufsize0 = bufsize;

	va_start(ap, fmt);

	while (*fmt) {
		switch ((c=*fmt++)) {
		case 'b':
			len = 1;
			bt = va_arg(ap, uint8 *);
			if (bufsize < len)
				goto no_space;
			*bt = SVAL(buf, 0);
			break;
		case 'w':
			len = 2;
			w = va_arg(ap, uint16 *);
			if (bufsize < len)
				goto no_space;
			*w = SVAL(buf, 0);
			break;
		case 'd':
			len = 4;
			d = va_arg(ap, uint32 *);
			if (bufsize < len)
				goto no_space;
			*d = IVAL(buf, 0);
			break;
		case 'p':
			len = 4;
			p = va_arg(ap, void **);
			if (bufsize < len)
				goto no_space;
			/*
			 * This isn't a real pointer - only a token (1 or 0)
			 * to mark the fact a pointer is present.
			 */

			*p = (void *)(IVAL(buf, 0) ? (void *)1 : NULL);
			break;
		case 'P':
			/* Return malloc'ed string. */
			ps = va_arg(ap,char **);
			len = strlen((const char *)buf) + 1;
			*ps = SMB_STRDUP((const char *)buf);
			break;
		case 'f':
			s = va_arg(ap,char *);
			len = strlen((const char *)buf) + 1;
			if (bufsize < len || len > sizeof(fstring))
				goto no_space;
			memcpy(s, buf, len);
			break;
		case 'B':
			i = va_arg(ap, int *);
			b = va_arg(ap, char **);
			len = 4;
			if (bufsize < len)
				goto no_space;
			*i = IVAL(buf, 0);
			if (! *i) {
				*b = NULL;
				break;
			}
			len += *i;
			if (bufsize < len)
				goto no_space;
			*b = (char *)SMB_MALLOC(*i);
			if (! *b)
				goto no_space;
			memcpy(*b, buf+4, *i);
			break;
		default:
			DEBUG(0,("Unknown tdb_unpack format %c in %s\n",
				 c, fmt));

			len = 0;
			break;
		}

		buf += len;
		bufsize -= len;
	}

	va_end(ap);

	DEBUG(18,("tdb_unpack(%s, %d) -> %d\n",
		 fmt0, bufsize0, (int)PTR_DIFF(buf, buf0)));

	return PTR_DIFF(buf, buf0);

 no_space:
	va_end(ap);
	return -1;
}


/****************************************************************************
 Log tdb messages via DEBUG().
****************************************************************************/

static void tdb_log(TDB_CONTEXT *tdb, enum tdb_debug_level level, const char *format, ...)
{
	va_list ap;
	char *ptr = NULL;
	int ret;

	va_start(ap, format);
	ret = vasprintf(&ptr, format, ap);
	va_end(ap);

	if ((ret == -1) || !*ptr)
		return;

	DEBUG((int)level, ("tdb(%s): %s", tdb_name(tdb) ? tdb_name(tdb) : "unnamed", ptr));
	SAFE_FREE(ptr);
}

/****************************************************************************
 Like tdb_open() but also setup a logging function that redirects to
 the samba DEBUG() system.
****************************************************************************/

TDB_CONTEXT *tdb_open_log(const char *name, int hash_size, int tdb_flags,
			  int open_flags, mode_t mode)
{
	TDB_CONTEXT *tdb;
	struct tdb_logging_context log_ctx;

	if (!lp_use_mmap())
		tdb_flags |= TDB_NOMMAP;

	log_ctx.log_fn = tdb_log;
	log_ctx.log_private = NULL;

	if ((hash_size == 0) && (name != NULL)) {
		const char *base = strrchr_m(name, '/');
		if (base != NULL) {
			base += 1;
		}
		else {
			base = name;
		}
		hash_size = lp_parm_int(-1, "tdb_hashsize", base, 0);
	}

	tdb = tdb_open_ex(name, hash_size, tdb_flags, 
			  open_flags, mode, &log_ctx, NULL);
	if (!tdb)
		return NULL;

	return tdb;
}


/**
 * Search across the whole tdb for keys that match the given pattern
 * return the result as a list of keys
 *
 * @param tdb pointer to opened tdb file context
 * @param pattern searching pattern used by fnmatch(3) functions
 *
 * @return list of keys found by looking up with given pattern
 **/
TDB_LIST_NODE *tdb_search_keys(TDB_CONTEXT *tdb, const char* pattern)
{
	TDB_DATA key, next;
	TDB_LIST_NODE *list = NULL;
	TDB_LIST_NODE *rec = NULL;
	
	for (key = tdb_firstkey(tdb); key.dptr; key = next) {
		/* duplicate key string to ensure null-termination */
		char *key_str = SMB_STRNDUP((const char *)key.dptr, key.dsize);
		if (!key_str) {
			DEBUG(0, ("tdb_search_keys: strndup() failed!\n"));
			smb_panic("strndup failed!\n");
		}
		
		DEBUG(18, ("checking %s for match to pattern %s\n", key_str, pattern));
		
		next = tdb_nextkey(tdb, key);

		/* do the pattern checking */
		if (fnmatch(pattern, key_str, 0) == 0) {
			rec = SMB_MALLOC_P(TDB_LIST_NODE);
			ZERO_STRUCTP(rec);

			rec->node_key = key;
	
			DLIST_ADD_END(list, rec, TDB_LIST_NODE *);
		
			DEBUG(18, ("checking %s matched pattern %s\n", key_str, pattern));
		} else {
			free(key.dptr);
		}
		
		/* free duplicated key string */
		free(key_str);
	}
	
	return list;

}


/**
 * Free the list returned by tdb_search_keys
 *
 * @param node list of results found by tdb_search_keys
 **/
void tdb_search_list_free(TDB_LIST_NODE* node)
{
	TDB_LIST_NODE *next_node;
	
	while (node) {
		next_node = node->next;
		SAFE_FREE(node->node_key.dptr);
		SAFE_FREE(node);
		node = next_node;
	};
}

/****************************************************************************
 tdb_store, wrapped in a transaction. This way we make sure that a process
 that dies within writing does not leave a corrupt tdb behind.
****************************************************************************/

int tdb_trans_store(struct tdb_context *tdb, TDB_DATA key, TDB_DATA dbuf,
		    int flag)
{
	int res;

	if ((res = tdb_transaction_start(tdb)) != 0) {
		DEBUG(5, ("tdb_transaction_start failed\n"));
		return res;
	}

	if ((res = tdb_store(tdb, key, dbuf, flag)) != 0) {
		DEBUG(10, ("tdb_store failed\n"));
		if (tdb_transaction_cancel(tdb) != 0) {
			smb_panic("Cancelling transaction failed");
		}
		return res;
	}

	if ((res = tdb_transaction_commit(tdb)) != 0) {
		DEBUG(5, ("tdb_transaction_commit failed\n"));
	}

	return res;
}

/****************************************************************************
 tdb_delete, wrapped in a transaction. This way we make sure that a process
 that dies within deleting does not leave a corrupt tdb behind.
****************************************************************************/

int tdb_trans_delete(struct tdb_context *tdb, TDB_DATA key)
{
	int res;

	if ((res = tdb_transaction_start(tdb)) != 0) {
		DEBUG(5, ("tdb_transaction_start failed\n"));
		return res;
	}

	if ((res = tdb_delete(tdb, key)) != 0) {
		DEBUG(10, ("tdb_delete failed\n"));
		if (tdb_transaction_cancel(tdb) != 0) {
			smb_panic("Cancelling transaction failed");
		}
		return res;
	}

	if ((res = tdb_transaction_commit(tdb)) != 0) {
		DEBUG(5, ("tdb_transaction_commit failed\n"));
	}

	return res;
}

/*
 Log tdb messages via DEBUG().
*/
static void tdb_wrap_log(TDB_CONTEXT *tdb, enum tdb_debug_level level, 
			 const char *format, ...) PRINTF_ATTRIBUTE(3,4);

static void tdb_wrap_log(TDB_CONTEXT *tdb, enum tdb_debug_level level, 
			 const char *format, ...)
{
	va_list ap;
	char *ptr = NULL;
	int debuglevel = 0;
	int ret;

	switch (level) {
	case TDB_DEBUG_FATAL:
		debuglevel = 0;
		break;
	case TDB_DEBUG_ERROR:
		debuglevel = 1;
		break;
	case TDB_DEBUG_WARNING:
		debuglevel = 2;
		break;
	case TDB_DEBUG_TRACE:
		debuglevel = 5;
		break;
	default:
		debuglevel = 0;
	}		

	va_start(ap, format);
	ret = vasprintf(&ptr, format, ap);
	va_end(ap);

	if (ret != -1) {
		const char *name = tdb_name(tdb);
		DEBUG(debuglevel, ("tdb(%s): %s", name ? name : "unnamed", ptr));
		free(ptr);
	}
}

static struct tdb_wrap *tdb_list;

/* destroy the last connection to a tdb */
static int tdb_wrap_destructor(struct tdb_wrap *w)
{
	tdb_close(w->tdb);
	DLIST_REMOVE(tdb_list, w);
	return 0;
}				 

/*
  wrapped connection to a tdb database
  to close just talloc_free() the tdb_wrap pointer
 */
struct tdb_wrap *tdb_wrap_open(TALLOC_CTX *mem_ctx,
			       const char *name, int hash_size, int tdb_flags,
			       int open_flags, mode_t mode)
{
	struct tdb_wrap *w;
	struct tdb_logging_context log_ctx;
	log_ctx.log_fn = tdb_wrap_log;

	if (!lp_use_mmap())
		tdb_flags |= TDB_NOMMAP;

	for (w=tdb_list;w;w=w->next) {
		if (strcmp(name, w->name) == 0) {
			/*
			 * Yes, talloc_reference is exactly what we want
			 * here. Otherwise we would have to implement our own
			 * reference counting.
			 */
			return talloc_reference(mem_ctx, w);
		}
	}

	w = talloc(mem_ctx, struct tdb_wrap);
	if (w == NULL) {
		return NULL;
	}

	if (!(w->name = talloc_strdup(w, name))) {
		talloc_free(w);
		return NULL;
	}

	if ((hash_size == 0) && (name != NULL)) {
		const char *base = strrchr_m(name, '/');
		if (base != NULL) {
			base += 1;
		}
		else {
			base = name;
		}
		hash_size = lp_parm_int(-1, "tdb_hashsize", base, 0);
	}

	w->tdb = tdb_open_ex(name, hash_size, tdb_flags, 
			     open_flags, mode, &log_ctx, NULL);
	if (w->tdb == NULL) {
		talloc_free(w);
		return NULL;
	}

	talloc_set_destructor(w, tdb_wrap_destructor);

	DLIST_ADD(tdb_list, w);

	return w;
}

NTSTATUS map_nt_error_from_tdb(enum TDB_ERROR err)
{
	struct { enum TDB_ERROR err; NTSTATUS status; }	map[] =
		{ { TDB_SUCCESS,	NT_STATUS_OK },
		  { TDB_ERR_CORRUPT,	NT_STATUS_INTERNAL_DB_CORRUPTION },
		  { TDB_ERR_IO,		NT_STATUS_UNEXPECTED_IO_ERROR },
		  { TDB_ERR_OOM,	NT_STATUS_NO_MEMORY },
		  { TDB_ERR_EXISTS,	NT_STATUS_OBJECT_NAME_COLLISION },

		  /*
		   * TDB_ERR_LOCK is very broad, we could for example
		   * distinguish between fcntl locks and invalid lock
		   * sequences. So NT_STATUS_FILE_LOCK_CONFLICT is a
		   * compromise.
		   */
		  { TDB_ERR_LOCK,	NT_STATUS_FILE_LOCK_CONFLICT },
		  /*
		   * The next two ones in the enum are not actually used
		   */
		  { TDB_ERR_NOLOCK,	NT_STATUS_FILE_LOCK_CONFLICT },
		  { TDB_ERR_LOCK_TIMEOUT, NT_STATUS_FILE_LOCK_CONFLICT },
		  { TDB_ERR_NOEXIST,	NT_STATUS_NOT_FOUND },
		  { TDB_ERR_EINVAL,	NT_STATUS_INVALID_PARAMETER },
		  { TDB_ERR_RDONLY,	NT_STATUS_ACCESS_DENIED }
		};

	int i;

	for (i=0; i < sizeof(map) / sizeof(map[0]); i++) {
		if (err == map[i].err) {
			return map[i].status;
		}
	}

	return NT_STATUS_INTERNAL_ERROR;
}


/*********************************************************************
 * the following is a generic validation mechanism for tdbs.
 *********************************************************************/

/* 
 * internal validation function, executed by the child.  
 */
static int tdb_validate_child(struct tdb_context *tdb,
			      tdb_validate_data_func validate_fn)
{
	int ret = 1;
	int num_entries = 0;
	struct tdb_validation_status v_status;

	v_status.tdb_error = False;
	v_status.bad_freelist = False;
	v_status.bad_entry = False;
	v_status.unknown_key = False;
	v_status.success = True;

	if (!tdb) {
		v_status.tdb_error = True;
		v_status.success = False;
		goto out;
	}

	/* Check if the tdb's freelist is good. */
	if (tdb_validate_freelist(tdb, &num_entries) == -1) {
		v_status.bad_freelist = True;
		v_status.success = False;
		goto out;
	}

	DEBUG(10,("tdb_validate_child: tdb %s freelist has %d entries\n",
		  tdb_name(tdb), num_entries));

	/* Now traverse the tdb to validate it. */
	num_entries = tdb_traverse(tdb, validate_fn, (void *)&v_status);
	if (!v_status.success) {
		goto out;
	} else if (num_entries == -1) {
		v_status.tdb_error = True;
		v_status.success = False;
		goto out;
	}

	DEBUG(10,("tdb_validate_child: tdb %s is good with %d entries\n",
		  tdb_name(tdb), num_entries));
	ret = 0; /* Cache is good. */

out:
	DEBUG(10,   ("tdb_validate_child: summary of validation status:\n"));
	DEBUGADD(10,(" * tdb error: %s\n", v_status.tdb_error ? "yes" : "no"));
	DEBUGADD(10,(" * bad freelist: %s\n",v_status.bad_freelist?"yes":"no"));
	DEBUGADD(10,(" * bad entry: %s\n", v_status.bad_entry ? "yes" : "no"));
	DEBUGADD(10,(" * unknown key: %s\n", v_status.unknown_key?"yes":"no"));
	DEBUGADD(10,(" => overall success: %s\n", v_status.success?"yes":"no"));

	return ret;
}

/*
 * tdb validation function.
 * returns 0 if tdb is ok, != 0 if it isn't.
 * this function expects an opened tdb.
 */
int tdb_validate(struct tdb_context *tdb, tdb_validate_data_func validate_fn)
{
	pid_t child_pid = -1;
	int child_status = 0;
	int wait_pid = 0;
	int ret = 1;

	if (tdb == NULL) {
		DEBUG(1, ("Error: tdb_validate called with tdb == NULL\n"));
		return ret;
	}

	DEBUG(5, ("tdb_validate called for tdb '%s'\n", tdb_name(tdb)));

	/* fork and let the child do the validation.
	 * benefit: no need to twist signal handlers and panic functions.
	 * just let the child panic. we catch the signal. */

	DEBUG(10, ("tdb_validate: forking to let child do validation.\n"));
	child_pid = sys_fork();
	if (child_pid == 0) {
		/* child code */
		DEBUG(10, ("tdb_validate (validation child): created\n"));
		DEBUG(10, ("tdb_validate (validation child): "
			   "calling tdb_validate_child\n"));
		exit(tdb_validate_child(tdb, validate_fn));
	}
	else if (child_pid < 0) {
		DEBUG(1, ("tdb_validate: fork for validation failed.\n"));
		goto done;
	}

	/* parent */

	DEBUG(10, ("tdb_validate: fork succeeded, child PID = %d\n",child_pid));

	DEBUG(10, ("tdb_validate: waiting for child to finish...\n"));
	while  ((wait_pid = sys_waitpid(child_pid, &child_status, 0)) < 0) {
		if (errno == EINTR) {
			DEBUG(10, ("tdb_validate: got signal during waitpid, "
				   "retrying\n"));
			errno = 0;
			continue;
		}
		DEBUG(1, ("tdb_validate: waitpid failed with error '%s'.\n",
			  strerror(errno)));
		goto done;
	}
	if (wait_pid != child_pid) {
		DEBUG(1, ("tdb_validate: waitpid returned pid %d, "
			  "but %d was expected\n", wait_pid, child_pid));
		goto done;
	}

	DEBUG(10, ("tdb_validate: validating child returned.\n"));
	if (WIFEXITED(child_status)) {
		DEBUG(10, ("tdb_validate: child exited, code %d.\n",
			   WEXITSTATUS(child_status)));
		ret = WEXITSTATUS(child_status);
	}
	if (WIFSIGNALED(child_status)) {
		DEBUG(10, ("tdb_validate: child terminated by signal %d\n",
			   WTERMSIG(child_status)));
#ifdef WCOREDUMP
		if (WCOREDUMP(child_status)) {
			DEBUGADD(10, ("core dumped\n"));
		}
#endif
		ret = WTERMSIG(child_status);
	}
	if (WIFSTOPPED(child_status)) {
		DEBUG(10, ("tdb_validate: child was stopped by signal %d\n",
			   WSTOPSIG(child_status)));
		ret = WSTOPSIG(child_status);
	}

done:
	DEBUG(5, ("tdb_validate returning code '%d' for tdb '%s'\n", ret,
		  tdb_name(tdb)));

	return ret;
}

/*
 * tdb validation function.
 * returns 0 if tdb is ok, != 0 if it isn't.
 * this is a wrapper around the actual validation function that opens and closes
 * the tdb.
 */
int tdb_validate_open(const char *tdb_path, tdb_validate_data_func validate_fn)
{
	TDB_CONTEXT *tdb = NULL;
	int ret = 1;

	DEBUG(5, ("tdb_validate_open called for tdb '%s'\n", tdb_path));

	tdb = tdb_open_log(tdb_path, 0, TDB_DEFAULT, O_RDONLY, 0);
	if (!tdb) {
		DEBUG(1, ("Error opening tdb %s\n", tdb_path));
		return ret;
	}

	ret = tdb_validate(tdb, validate_fn);
	tdb_close(tdb);
	return ret;
}

/*
 * tdb backup function and helpers for tdb_validate wrapper with backup
 * handling.
 */

/* this structure eliminates the need for a global overall status for
 * the traverse-copy */
struct tdb_copy_data {
	struct tdb_context *dst;
	bool success;
};

static int traverse_copy_fn(struct tdb_context *tdb, TDB_DATA key,
			    TDB_DATA dbuf, void *private_data)
{
	struct tdb_copy_data *data = (struct tdb_copy_data *)private_data;

	if (tdb_store(data->dst, key, dbuf, TDB_INSERT) != 0) {
		DEBUG(4, ("Failed to insert into %s: %s\n", tdb_name(data->dst),
			  strerror(errno)));
		data->success = False;
		return 1;
	}
	return 0;
}

static int tdb_copy(struct tdb_context *src, struct tdb_context *dst)
{
	struct tdb_copy_data data;
	int count;

	data.dst = dst;
	data.success = True;

	count = tdb_traverse(src, traverse_copy_fn, (void *)(&data));
	if ((count < 0) || (data.success == False)) {
		return -1;
	}
	return count;
}

static int tdb_verify_basic(struct tdb_context *tdb)
{
	return tdb_traverse(tdb, NULL, NULL);
}

/* this backup function is essentially taken from lib/tdb/tools/tdbbackup.tdb
 */
static int tdb_backup(TALLOC_CTX *ctx, const char *src_path,
		      const char *dst_path, int hash_size)
{
	struct tdb_context *src_tdb = NULL;
	struct tdb_context *dst_tdb = NULL;
	char *tmp_path = NULL;
	struct stat st;
	int count1, count2;
	int saved_errno = 0;
	int ret = -1;

	if (stat(src_path, &st) != 0) {
		DEBUG(3, ("Could not stat '%s': %s\n", src_path,
			  strerror(errno)));
		goto done;
	}

	/* open old tdb RDWR - so we can lock it */
	src_tdb = tdb_open_log(src_path, 0, TDB_DEFAULT, O_RDWR, 0);
	if (src_tdb == NULL) {
		DEBUG(3, ("Failed to open tdb '%s'\n", src_path));
		goto done;
	}

	if (tdb_lockall(src_tdb) != 0) {
		DEBUG(3, ("Failed to lock tdb '%s'\n", src_path));
		goto done;
	}

	tmp_path = talloc_asprintf(ctx, "%s%s", dst_path, ".tmp");
	unlink(tmp_path);
	dst_tdb = tdb_open_log(tmp_path,
			       hash_size ? hash_size : tdb_hash_size(src_tdb),
			       TDB_DEFAULT, O_RDWR | O_CREAT | O_EXCL,
			       st.st_mode & 0777);
	if (dst_tdb == NULL) {
		DEBUG(3, ("Error creating tdb '%s': %s\n", tmp_path,
			  strerror(errno)));
		saved_errno = errno;
		unlink(tmp_path);
		goto done;
	}

	count1 = tdb_copy(src_tdb, dst_tdb);
	if (count1 < 0) {
		DEBUG(3, ("Failed to copy tdb '%s': %s\n", src_path,
			  strerror(errno)));
		tdb_close(dst_tdb);
		goto done;
	}

	/* reopen ro and do basic verification */
	tdb_close(dst_tdb);
	dst_tdb = tdb_open_log(tmp_path, 0, TDB_DEFAULT, O_RDONLY, 0);
	if (!dst_tdb) {
		DEBUG(3, ("Failed to reopen tdb '%s': %s\n", tmp_path,
			  strerror(errno)));
		goto done;
	}
	count2 = tdb_verify_basic(dst_tdb);
	if (count2 != count1) {
		DEBUG(3, ("Failed to verify result of copying tdb '%s'.\n",
			  src_path));
		tdb_close(dst_tdb);
		goto done;
	}

	DEBUG(10, ("tdb_backup: successfully copied %d entries\n", count1));

	/* make sure the new tdb has reached stable storage
	 * then rename it to its destination */
	fsync(tdb_fd(dst_tdb));
	tdb_close(dst_tdb);
	unlink(dst_path);
	if (rename(tmp_path, dst_path) != 0) {
		DEBUG(3, ("Failed to rename '%s' to '%s': %s\n",
			  tmp_path, dst_path, strerror(errno)));
		goto done;
	}

	/* success */
	ret = 0;

done:
	if (src_tdb != NULL) {
		tdb_close(src_tdb);
	}
	if (tmp_path != NULL) {
		unlink(tmp_path);
		TALLOC_FREE(tmp_path);
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int rename_file_with_suffix(TALLOC_CTX *ctx, const char *path,
				   const char *suffix)
{
	int ret = -1;
	char *dst_path;

	dst_path = talloc_asprintf(ctx, "%s%s", path, suffix);

	ret = (rename(path, dst_path) != 0);

	if (ret == 0) {
		DEBUG(5, ("moved '%s' to '%s'\n", path, dst_path));
	} else if (errno == ENOENT) {
		DEBUG(3, ("file '%s' does not exist - so not moved\n", path));
		ret = 0;
	} else {
		DEBUG(3, ("error renaming %s to %s: %s\n", path, dst_path,
			  strerror(errno)));
	}

	TALLOC_FREE(dst_path);
	return ret;
}

/*
 * do a backup of a tdb, moving the destination out of the way first
 */
static int tdb_backup_with_rotate(TALLOC_CTX *ctx, const char *src_path,
		      		  const char *dst_path, int hash_size,
				  const char *rotate_suffix,
				  bool retry_norotate_if_nospc,
				  bool rename_as_last_resort_if_nospc)
{
	int ret;

        rename_file_with_suffix(ctx, dst_path, rotate_suffix);

        ret = tdb_backup(ctx, src_path, dst_path, hash_size);

	if (ret != 0) {
		DEBUG(10, ("backup of %s failed: %s\n", src_path, strerror(errno)));
	}
        if ((ret != 0) && (errno == ENOSPC) && retry_norotate_if_nospc)
        {
                char *rotate_path = talloc_asprintf(ctx, "%s%s", dst_path,
                                                    rotate_suffix);
                DEBUG(10, ("backup of %s failed due to lack of space\n",
			   src_path));
                DEBUGADD(10, ("trying to free some space by removing rotated "
			      "dst %s\n", rotate_path));
                if (unlink(rotate_path) == -1) {
                        DEBUG(10, ("unlink of %s failed: %s\n", rotate_path,
				   strerror(errno)));
                } else {
                        ret = tdb_backup(ctx, src_path, dst_path, hash_size);
                }
                TALLOC_FREE(rotate_path);
        }

        if ((ret != 0) && (errno == ENOSPC) && rename_as_last_resort_if_nospc)
        {
                DEBUG(10, ("backup of %s failed due to lack of space\n", 
			   src_path));
                DEBUGADD(10, ("using 'rename' as a last resort\n"));
                ret = rename(src_path, dst_path);
        }

        return ret;
}

/*
 * validation function with backup handling:
 *
 *  - calls tdb_validate
 *  - if the tdb is ok, create a backup "name.bak", possibly moving
 *    existing backup to name.bak.old,
 *    return 0 (success) even if the backup fails
 *  - if the tdb is corrupt:
 *    - move the tdb to "name.corrupt"
 *    - check if there is valid backup.
 *      if so, restore the backup.
 *      if restore is successful, return 0 (success),
 *    - otherwise return -1 (failure)
 */
int tdb_validate_and_backup(const char *tdb_path,
			    tdb_validate_data_func validate_fn)
{
	int ret = -1;
	const char *backup_suffix = ".bak";
	const char *corrupt_suffix = ".corrupt";
	const char *rotate_suffix = ".old";
	char *tdb_path_backup;
	struct stat st;
	TALLOC_CTX *ctx = NULL;

	ctx = talloc_new(NULL);
	if (ctx == NULL) {
		DEBUG(0, ("tdb_validate_and_backup: out of memory\n"));
		goto done;
	}

	tdb_path_backup = talloc_asprintf(ctx, "%s%s", tdb_path, backup_suffix);

	ret = tdb_validate_open(tdb_path, validate_fn);

	if (ret == 0) {
		DEBUG(1, ("tdb '%s' is valid\n", tdb_path));
		ret = tdb_backup_with_rotate(ctx, tdb_path, tdb_path_backup, 0,
					     rotate_suffix, True, False);
		if (ret != 0) {
			DEBUG(1, ("Error creating backup of tdb '%s'\n",
				  tdb_path));
			/* the actual validation was successful: */
			ret = 0;
		} else {
			DEBUG(1, ("Created backup '%s' of tdb '%s'\n",
				  tdb_path_backup, tdb_path));
		}
	} else {
		DEBUG(1, ("tdb '%s' is invalid\n", tdb_path));

		ret =stat(tdb_path_backup, &st);
		if (ret != 0) {
			DEBUG(5, ("Could not stat '%s': %s\n", tdb_path_backup,
				  strerror(errno)));
			DEBUG(1, ("No backup found.\n"));
		} else {
			DEBUG(1, ("backup '%s' found.\n", tdb_path_backup));
			ret = tdb_validate_open(tdb_path_backup, validate_fn);
			if (ret != 0) {
				DEBUG(1, ("Backup '%s' is invalid.\n",
					  tdb_path_backup));
			}
		}

		if (ret != 0) {
			int renamed = rename_file_with_suffix(ctx, tdb_path,
							      corrupt_suffix);
			if (renamed != 0) {
				DEBUG(1, ("Error moving tdb to '%s%s'\n",
					  tdb_path, corrupt_suffix));
			} else {
				DEBUG(1, ("Corrupt tdb stored as '%s%s'\n",
					  tdb_path, corrupt_suffix));
			}
			goto done;
		}

		DEBUG(1, ("valid backup '%s' found\n", tdb_path_backup));
		ret = tdb_backup_with_rotate(ctx, tdb_path_backup, tdb_path, 0,
					     corrupt_suffix, True, True);
		if (ret != 0) {
			DEBUG(1, ("Error restoring backup from '%s'\n",
				  tdb_path_backup));
		} else {
			DEBUG(1, ("Restored tdb backup from '%s'\n",
				  tdb_path_backup));
		}
	}

done:
	TALLOC_FREE(ctx);
	return ret;
}
