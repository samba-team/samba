/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   tdb utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/* these are little tdb utility functions that are meant to make
   dealing with a tdb database a little less cumbersome in Samba */

/****************************************************************************
 Lock a chain by string.
****************************************************************************/

int tdb_lock_bystring(TDB_CONTEXT *tdb, char *keyval)
{
	TDB_DATA key;

	key.dptr = keyval;
	key.dsize = strlen(keyval)+1;
	
	return tdb_chainlock(tdb, key);
}

/****************************************************************************
 Unlock a chain by string.
****************************************************************************/

void tdb_unlock_bystring(TDB_CONTEXT *tdb, char *keyval)
{
	TDB_DATA key;

	key.dptr = keyval;
	key.dsize = strlen(keyval)+1;
	
	tdb_chainunlock(tdb, key);
}

/****************************************************************************
 Fetch a value by a arbitrary blob key, return -1 if not found.
****************************************************************************/

int tdb_fetch_int_byblob(TDB_CONTEXT *tdb, char *keyval, size_t len)
{
	TDB_DATA key, data;
	int ret;

	key.dptr = keyval;
	key.dsize = len;
	data = tdb_fetch(tdb, key);
	if (!data.dptr || data.dsize != sizeof(int))
		return -1;
	
	memcpy(&ret, data.dptr, sizeof(int));
	free(data.dptr);
	return ret;
}

/****************************************************************************
 Fetch a value by string key, return -1 if not found.
****************************************************************************/

int tdb_fetch_int(TDB_CONTEXT *tdb, char *keystr)
{
	return tdb_fetch_int_byblob(tdb, keystr, strlen(keystr) + 1);
}

/****************************************************************************
 Store a value by an arbitary blob key, return 0 on success, -1 on failure.
****************************************************************************/

int tdb_store_int_byblob(TDB_CONTEXT *tdb, char *keystr, size_t len, int v)
{
	TDB_DATA key, data;

	key.dptr = keystr;
	key.dsize = len;
	data.dptr = (void *)&v;
	data.dsize = sizeof(int);

	return tdb_store(tdb, key, data, TDB_REPLACE);
}

/****************************************************************************
 Store a value by string key, return 0 on success, -1 on failure.
****************************************************************************/

int tdb_store_int(TDB_CONTEXT *tdb, char *keystr, int v)
{
	return tdb_store_int_byblob(tdb, keystr, strlen(keystr) + 1, v);
}

/****************************************************************************
 Store a buffer by a null terminated string key.  Return 0 on success, -1
 on failure.
****************************************************************************/

int tdb_store_by_string(TDB_CONTEXT *tdb, char *keystr, void *buffer, int len)
{
    TDB_DATA key, data;

    key.dptr = keystr;
    key.dsize = strlen(keystr) + 1;

    data.dptr = buffer;
    data.dsize = len;

    return tdb_store(tdb, key, data, TDB_REPLACE);
}

/****************************************************************************
 Fetch a buffer using a null terminated string key.  Don't forget to call
 free() on the result dptr.
****************************************************************************/

TDB_DATA tdb_fetch_by_string(TDB_CONTEXT *tdb, char *keystr)
{
    TDB_DATA key;

    key.dptr = keystr;
    key.dsize = strlen(keystr) + 1;

    return tdb_fetch(tdb, key);
}

/****************************************************************************
 Atomic integer change. Returns old value. To create, set initial value in *oldval. 
****************************************************************************/

int tdb_change_int_atomic(TDB_CONTEXT *tdb, char *keystr, int *oldval, int change_val)
{
	int val;
	int ret = -1;

	if (tdb_lock_bystring(tdb, keystr) == -1)
		return -1;

	if ((val = tdb_fetch_int(tdb, keystr)) == -1) {
		if (tdb_error(tdb) != TDB_ERR_NOEXIST)
			goto err_out;

		val = *oldval;

	} else {
		*oldval = val;
		val += change_val;
	}
		
	if (tdb_store_int(tdb, keystr, val) == -1)
		goto err_out;

	ret = 0;

  err_out:

	tdb_unlock_bystring(tdb, keystr);
	return ret;
}

/****************************************************************************
 Useful pair of routines for packing/unpacking data consisting of
 integers and strings.
****************************************************************************/

size_t tdb_pack(char *buf, int bufsize, char *fmt, ...)
{
	va_list ap;
	uint16 w;
	uint32 d;
	int i;
	void *p;
	int len;
	char *s;
	char c;
	char *buf0 = buf;
	char *fmt0 = fmt;
	int bufsize0 = bufsize;

	va_start(ap, fmt);

	while (*fmt) {
		switch ((c = *fmt++)) {
		case 'w':
			len = 2;
			w = (uint16)va_arg(ap, int);
			if (bufsize >= len)
				SSVAL(buf, 0, w);
			break;
		case 'd':
			len = 4;
			d = va_arg(ap, uint32);
			if (bufsize >= len)
				SIVAL(buf, 0, d);
			break;
		case 'p':
			len = 4;
			p = va_arg(ap, void *);
			d = p?1:0;
			if (bufsize >= len)
				SIVAL(buf, 0, d);
			break;
		case 'P':
			s = va_arg(ap,char *);
			w = strlen(s);
			len = w + 1;
			if (bufsize >= len)
				memcpy(buf, s, len);
			break;
		case 'f':
			s = va_arg(ap,char *);
			w = strlen(s);
			len = w + 1;
			if (bufsize >= len)
				memcpy(buf, s, len);
			break;
		case 'B':
			i = va_arg(ap, int);
			s = va_arg(ap, char *);
			len = 4+i;
			if (bufsize >= len) {
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
		bufsize -= len;
	}

	va_end(ap);

	DEBUG(18,("tdb_pack(%s, %d) -> %d\n", 
		 fmt0, bufsize0, (int)PTR_DIFF(buf, buf0)));
	
	return PTR_DIFF(buf, buf0);
}

/****************************************************************************
 Useful pair of routines for packing/unpacking data consisting of
 integers and strings.
****************************************************************************/

int tdb_unpack(char *buf, int bufsize, char *fmt, ...)
{
	va_list ap;
	uint16 *w;
	uint32 *d;
	int len;
	int *i;
	void **p;
	char *s, **b;
	char c;
	char *buf0 = buf;
	char *fmt0 = fmt;
	int bufsize0 = bufsize;

	va_start(ap, fmt);
	
	while (*fmt) {
		switch ((c=*fmt++)) {
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
			*p = (void *)IVAL(buf, 0);
			break;
		case 'P':
			s = va_arg(ap,char *);
			len = strlen(buf) + 1;
			if (bufsize < len || len > sizeof(pstring))
				goto no_space;
			memcpy(s, buf, len);
			break;
		case 'f':
			s = va_arg(ap,char *);
			len = strlen(buf) + 1;
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
			*b = (char *)malloc(*i);
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
	return -1;
}

/****************************************************************************
 Log tdb messages via DEBUG().
****************************************************************************/

static void tdb_log(TDB_CONTEXT *tdb, int level, const char *format, ...)
{
	va_list ap;
	char *ptr = NULL;

	va_start(ap, format);
	vasprintf(&ptr, format, ap);
	va_end(ap);
	
	if (!ptr || !*ptr)
		return;

	DEBUG(level, ("tdb(%s): %s", tdb->name, ptr));
	free(ptr);
}

/****************************************************************************
 Like tdb_open() but also setup a logging function that redirects to
 the samba DEBUG() system.
****************************************************************************/

TDB_CONTEXT *tdb_open_log(char *name, int hash_size, int tdb_flags,
			  int open_flags, mode_t mode)
{
	TDB_CONTEXT *tdb;

	if (!lp_use_mmap())
		tdb_flags |= TDB_NOMMAP;

	tdb = tdb_open(name, hash_size, tdb_flags, 
				    open_flags, mode);
	if (!tdb)
		return NULL;

	tdb_logging_function(tdb, tdb_log);

	return tdb;
}


/****************************************************************************
 Allow tdb_delete to be used as a tdb_traversal_fn.
****************************************************************************/

int tdb_traverse_delete_fn(TDB_CONTEXT *the_tdb, TDB_DATA key, TDB_DATA dbuf,
                     void *state)
{
    return tdb_delete(the_tdb, key);
}
