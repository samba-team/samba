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
#include "system/filesys.h"
#include "util_tdb.h"
#include "cbuf.h"

#undef malloc
#undef realloc
#undef calloc
#undef strdup

/****************************************************************************
 Useful pair of routines for packing/unpacking data consisting of
 integers and strings.
****************************************************************************/

static size_t tdb_pack_va(uint8_t *buf, int bufsize, const char *fmt, va_list ap)
{
	uint8_t bt;
	uint16_t w;
	uint32_t d;
	int i;
	void *p;
	int len = 0;
	char *s;
	char c;
	const char *fmt0 = fmt;
	int bufsize0 = bufsize;
	size_t to_write = 0;
	while (*fmt) {
		switch ((c = *fmt++)) {
		case 'b': /* unsigned 8-bit integer */
			len = 1;
			bt = (uint8_t)va_arg(ap, int);
			if (bufsize && bufsize >= len)
				SSVAL(buf, 0, bt);
			break;
		case 'w': /* unsigned 16-bit integer */
			len = 2;
			w = (uint16_t)va_arg(ap, int);
			if (bufsize && bufsize >= len)
				SSVAL(buf, 0, w);
			break;
		case 'd': /* signed 32-bit integer (standard int in most systems) */
			len = 4;
			d = va_arg(ap, uint32_t);
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
		case 'f': /* null-terminated string */
			s = va_arg(ap,char *);
			if (s == NULL) {
				smb_panic("Invalid argument");
			}
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
				if (s != NULL) {
					memcpy(buf+4, s, i);
				}
			}
			break;
		default:
			DEBUG(0,("Unknown tdb_pack format %c in %s\n", 
				 c, fmt));
			len = 0;
			break;
		}

		to_write += len;
		if (bufsize > 0) {
			bufsize -= len;
			buf += len;
		}
		if (bufsize < 0)
			bufsize = 0;
	}

	DEBUG(18,("tdb_pack_va(%s, %d) -> %d\n", 
		 fmt0, bufsize0, (int)to_write));

	return to_write;
}

size_t tdb_pack(uint8_t *buf, int bufsize, const char *fmt, ...)
{
	va_list ap;
	size_t result;

	va_start(ap, fmt);
	result = tdb_pack_va(buf, bufsize, fmt, ap);
	va_end(ap);
	return result;
}

/****************************************************************************
 Useful pair of routines for packing/unpacking data consisting of
 integers and strings.
****************************************************************************/

int tdb_unpack(const uint8_t *buf, int in_bufsize, const char *fmt, ...)
{
	va_list ap;
	uint8_t *bt;
	uint16_t *w;
	uint32_t *d;
	size_t bufsize = in_bufsize;
	size_t len;
	uint32_t *i;
	void **p;
	char *s, **b, **ps;
	char c;
	const uint8_t *buf0 = buf;
	const char *fmt0 = fmt;

	va_start(ap, fmt);

	while (*fmt) {
		switch ((c=*fmt++)) {
		case 'b': /* unsigned 8-bit integer */
			len = 1;
			bt = va_arg(ap, uint8_t *);
			if (bufsize < len)
				goto no_space;
			*bt = SVAL(buf, 0);
			break;
		case 'w': /* unsigned 16-bit integer */
			len = 2;
			w = va_arg(ap, uint16_t *);
			if (bufsize < len)
				goto no_space;
			*w = SVAL(buf, 0);
			break;
		case 'd': /* unsigned 32-bit integer (standard int in most systems) */
			len = 4;
			d = va_arg(ap, uint32_t *);
			if (bufsize < len)
				goto no_space;
			*d = IVAL(buf, 0);
			break;
		case 'p': /* pointer */
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
		case 'P': /* null-terminated string */
			/* Return malloc'ed string. */
			ps = va_arg(ap,char **);
			len = strnlen((const char *)buf, bufsize) + 1;
			if (bufsize < len)
				goto no_space;
			if (ps != NULL) {
				*ps = SMB_STRDUP((const char *)buf);
				if (*ps == NULL) {
					goto no_space;
				}
			}
			break;
		case 'f': /* null-terminated string */
			s = va_arg(ap,char *);
			len = strnlen((const char *)buf, bufsize) + 1;
			if (bufsize < len || len > sizeof(fstring))
				goto no_space;
			if (s != NULL) {
				memcpy(s, buf, len);
			}
			break;
		case 'B': /* fixed-length string */
			i = va_arg(ap, uint32_t *);
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
			if (len < *i) {
				goto no_space;
			}
			if (bufsize < len)
				goto no_space;
			if (b != NULL) {
				*b = (char *)SMB_MALLOC(*i);
				if (! *b)
					goto no_space;
				memcpy(*b, buf+4, *i);
			}
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
		 fmt0, in_bufsize, (int)PTR_DIFF(buf, buf0)));

	return PTR_DIFF(buf, buf0);

 no_space:
	va_end(ap);
	return -1;
}


/****************************************************************************
 Log tdb messages via DEBUG().
****************************************************************************/

static void tdb_log(TDB_CONTEXT *tdb, enum tdb_debug_level level,
		    const char *format, ...) PRINTF_ATTRIBUTE(3,4);

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
	struct tdb_logging_context log_ctx = { .log_fn = tdb_log };

	if (!lp_use_mmap())
		tdb_flags |= TDB_NOMMAP;

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

int tdb_data_cmp(TDB_DATA t1, TDB_DATA t2)
{
	int ret;
	if (t1.dptr == NULL && t2.dptr != NULL) {
		return -1;
	}
	if (t1.dptr != NULL && t2.dptr == NULL) {
		return 1;
	}
	if (t1.dptr == t2.dptr) {
		return t1.dsize - t2.dsize;
	}
	ret = memcmp(t1.dptr, t2.dptr, MIN(t1.dsize, t2.dsize));
	if (ret == 0) {
		return t1.dsize - t2.dsize;
	}
	return ret;
}

char *tdb_data_string(TALLOC_CTX *mem_ctx, TDB_DATA d)
{
	int len;
	char *ret = NULL;
	cbuf *ost = cbuf_new(mem_ctx);

	if (ost == NULL) {
		return NULL;
	}

	len = cbuf_printf(ost, "%zu:", d.dsize);
	if (len == -1) {
		goto done;
	}

	if (d.dptr == NULL) {
		len = cbuf_puts(ost, "<NULL>", -1);
	} else {
		len = cbuf_print_quoted(ost, (const char*)d.dptr, d.dsize);
	}
	if (len == -1) {
		goto done;
	}

	cbuf_swapptr(ost, &ret, 0);
	talloc_steal(mem_ctx, ret);

done:
	talloc_free(ost);
	return ret;
}

static sig_atomic_t gotalarm;

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig(int signum)
{
	gotalarm = 1;
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
		CatchSignal(SIGALRM, gotalarm_sig);
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
		CatchSignal(SIGALRM, SIG_IGN);
		if (gotalarm && (ret != 0)) {
			DEBUG(0,("tdb_chainlock_with_timeout_internal: alarm (%u) timed out for key %s in tdb %s\n",
				timeout, key.dptr, tdb_name(tdb)));
			/* TODO: If we time out waiting for a lock, it might
			 * be nice to use F_GETLK to get the pid of the
			 * process currently holding the lock and print that
			 * as part of the debugging message. -- mbp */
			return -1;
		}
	}

	return ret == 0 ? 0 : -1;
}

/****************************************************************************
 Write lock a chain. Return non-zero if timeout or lock failed.
****************************************************************************/

int tdb_chainlock_with_timeout( TDB_CONTEXT *tdb, TDB_DATA key, unsigned int timeout)
{
	return tdb_chainlock_with_timeout_internal(tdb, key, timeout, F_WRLCK);
}

int tdb_lock_bystring_with_timeout(TDB_CONTEXT *tdb, const char *keyval,
				   int timeout)
{
	TDB_DATA key = string_term_tdb_data(keyval);

	return tdb_chainlock_with_timeout(tdb, key, timeout);
}

/****************************************************************************
 Read lock a chain by string. Return non-zero if timeout or lock failed.
****************************************************************************/

int tdb_read_lock_bystring_with_timeout(TDB_CONTEXT *tdb, const char *keyval, unsigned int timeout)
{
	TDB_DATA key = string_term_tdb_data(keyval);

	return tdb_chainlock_with_timeout_internal(tdb, key, timeout, F_RDLCK);
}
