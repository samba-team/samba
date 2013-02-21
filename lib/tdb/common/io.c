 /*
   Unix SMB/CIFS implementation.

   trivial database library

   Copyright (C) Andrew Tridgell              1999-2005
   Copyright (C) Paul `Rusty' Russell		   2000
   Copyright (C) Jeremy Allison			   2000-2003

     ** NOTE! The following LGPL license applies to the tdb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/


#include "tdb_private.h"

/*
 * We prepend the mutex area, so fixup offsets. See mutex.c for details.
 * tdb->hdr_ofs is 0 or header.mutex_size.
 *
 * Note: that we only have the 4GB limit of tdb_off_t for
 * tdb->map_size. The file size on disk can be 4GB + tdb->hdr_ofs!
 */

static bool tdb_adjust_offset(struct tdb_context *tdb, off_t *off)
{
	off_t tmp = tdb->hdr_ofs + *off;

	if ((tmp < tdb->hdr_ofs) || (tmp < *off)) {
		errno = EIO;
		return false;
	}

	*off = tmp;
	return true;
}

static ssize_t tdb_pwrite(struct tdb_context *tdb, const void *buf,
			  size_t count, off_t offset)
{
	if (!tdb_adjust_offset(tdb, &offset)) {
		return -1;
	}
	return pwrite(tdb->fd, buf, count, offset);
}

static ssize_t tdb_pread(struct tdb_context *tdb, void *buf,
			 size_t count, off_t offset)
{
	if (!tdb_adjust_offset(tdb, &offset)) {
		return -1;
	}
	return pread(tdb->fd, buf, count, offset);
}

static int tdb_ftruncate(struct tdb_context *tdb, off_t length)
{
	if (!tdb_adjust_offset(tdb, &length)) {
		return -1;
	}
	return ftruncate(tdb->fd, length);
}

static int tdb_fstat(struct tdb_context *tdb, struct stat *buf)
{
	int ret;

	ret = fstat(tdb->fd, buf);
	if (ret == -1) {
		return -1;
	}

	if (buf->st_size < tdb->hdr_ofs) {
		errno = EIO;
		return -1;
	}
	buf->st_size -= tdb->hdr_ofs;

	return ret;
}

/* check for an out of bounds access - if it is out of bounds then
   see if the database has been expanded by someone else and expand
   if necessary
*/
static int tdb_oob(struct tdb_context *tdb, tdb_off_t off, tdb_len_t len,
		   int probe)
{
	struct stat st;
	if (len + off < len) {
		if (!probe) {
			/* Ensure ecode is set for log fn. */
			tdb->ecode = TDB_ERR_IO;
			TDB_LOG((tdb, TDB_DEBUG_FATAL,"tdb_oob off %u len %u wrap\n",
				 off, len));
		}
		return -1;
	}

	if (off + len <= tdb->map_size)
		return 0;
	if (tdb->flags & TDB_INTERNAL) {
		if (!probe) {
			/* Ensure ecode is set for log fn. */
			tdb->ecode = TDB_ERR_IO;
			TDB_LOG((tdb, TDB_DEBUG_FATAL,"tdb_oob len %u beyond internal malloc size %u\n",
				 (int)(off + len), (int)tdb->map_size));
		}
		return -1;
	}

	if (tdb_fstat(tdb, &st) == -1) {
		tdb->ecode = TDB_ERR_IO;
		return -1;
	}

	/* Beware >4G files! */
	if ((tdb_off_t)st.st_size != st.st_size) {
		/* Ensure ecode is set for log fn. */
		tdb->ecode = TDB_ERR_IO;
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "tdb_oob len %llu too large!\n",
			 (long long)st.st_size));
		return -1;
	}

	/* Unmap, update size, remap.  We do this unconditionally, to handle
	 * the unusual case where the db is truncated.
	 *
	 * This can happen to a child using tdb_reopen_all(true) on a
	 * TDB_CLEAR_IF_FIRST tdb whose parent crashes: the next
	 * opener will truncate the database. */
	if (tdb_munmap(tdb) == -1) {
		tdb->ecode = TDB_ERR_IO;
		return -1;
	}
	tdb->map_size = st.st_size;
	if (tdb_mmap(tdb) != 0) {
		return -1;
	}

	if (st.st_size < (size_t)off + len) {
		if (!probe) {
			/* Ensure ecode is set for log fn. */
			tdb->ecode = TDB_ERR_IO;
			TDB_LOG((tdb, TDB_DEBUG_FATAL,"tdb_oob len %u beyond eof at %u\n",
				 (int)(off + len), (int)st.st_size));
		}
		return -1;
	}
	return 0;
}

/* write a lump of data at a specified offset */
static int tdb_write(struct tdb_context *tdb, tdb_off_t off,
		     const void *buf, tdb_len_t len)
{
	if (len == 0) {
		return 0;
	}

	if (tdb->read_only || tdb->traverse_read) {
		tdb->ecode = TDB_ERR_RDONLY;
		return -1;
	}

	if (tdb->methods->tdb_oob(tdb, off, len, 0) != 0)
		return -1;

	if (tdb->map_ptr) {
		memcpy(off + (char *)tdb->map_ptr, buf, len);
	} else {
#ifdef HAVE_INCOHERENT_MMAP
		tdb->ecode = TDB_ERR_IO;
		return -1;
#else
		ssize_t written;

		written = tdb_pwrite(tdb, buf, len, off);

		if ((written != (ssize_t)len) && (written != -1)) {
			/* try once more */
			tdb->ecode = TDB_ERR_IO;
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "tdb_write: wrote only "
				 "%zi of %u bytes at %u, trying once more\n",
				 written, len, off));
			written = tdb_pwrite(tdb, (const char *)buf+written,
					     len-written, off+written);
		}
		if (written == -1) {
			/* Ensure ecode is set for log fn. */
			tdb->ecode = TDB_ERR_IO;
			TDB_LOG((tdb, TDB_DEBUG_FATAL,"tdb_write failed at %u "
				 "len=%u (%s)\n", off, len, strerror(errno)));
			return -1;
		} else if (written != (ssize_t)len) {
			tdb->ecode = TDB_ERR_IO;
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "tdb_write: failed to "
				 "write %u bytes at %u in two attempts\n",
				 len, off));
			return -1;
		}
#endif
	}
	return 0;
}

/* Endian conversion: we only ever deal with 4 byte quantities */
void *tdb_convert(void *buf, uint32_t size)
{
	uint32_t i, *p = (uint32_t *)buf;
	for (i = 0; i < size / 4; i++)
		p[i] = TDB_BYTEREV(p[i]);
	return buf;
}


/* read a lump of data at a specified offset, maybe convert */
static int tdb_read(struct tdb_context *tdb, tdb_off_t off, void *buf,
		    tdb_len_t len, int cv)
{
	if (tdb->methods->tdb_oob(tdb, off, len, 0) != 0) {
		return -1;
	}

	if (tdb->map_ptr) {
		memcpy(buf, off + (char *)tdb->map_ptr, len);
	} else {
#ifdef HAVE_INCOHERENT_MMAP
		tdb->ecode = TDB_ERR_IO;
		return -1;
#else
		ssize_t ret;

		ret = tdb_pread(tdb, buf, len, off);
		if (ret != (ssize_t)len) {
			/* Ensure ecode is set for log fn. */
			tdb->ecode = TDB_ERR_IO;
			TDB_LOG((tdb, TDB_DEBUG_FATAL,"tdb_read failed at %u "
				 "len=%u ret=%zi (%s) map_size=%u\n",
				 off, len, ret, strerror(errno),
				 tdb->map_size));
			return -1;
		}
#endif
	}
	if (cv) {
		tdb_convert(buf, len);
	}
	return 0;
}



/*
  do an unlocked scan of the hash table heads to find the next non-zero head. The value
  will then be confirmed with the lock held
*/
static void tdb_next_hash_chain(struct tdb_context *tdb, uint32_t *chain)
{
	uint32_t h = *chain;
	if (tdb->map_ptr) {
		for (;h < tdb->hash_size;h++) {
			if (0 != *(uint32_t *)(TDB_HASH_TOP(h) + (unsigned char *)tdb->map_ptr)) {
				break;
			}
		}
	} else {
		uint32_t off=0;
		for (;h < tdb->hash_size;h++) {
			if (tdb_ofs_read(tdb, TDB_HASH_TOP(h), &off) != 0 || off != 0) {
				break;
			}
		}
	}
	(*chain) = h;
}


int tdb_munmap(struct tdb_context *tdb)
{
	if (tdb->flags & TDB_INTERNAL)
		return 0;

#ifdef HAVE_MMAP
	if (tdb->map_ptr) {
		int ret;

		ret = munmap(tdb->map_ptr, tdb->map_size);
		if (ret != 0)
			return ret;
	}
#endif
	tdb->map_ptr = NULL;
	return 0;
}

/* If mmap isn't coherent, *everyone* must always mmap. */
static bool should_mmap(const struct tdb_context *tdb)
{
#ifdef HAVE_INCOHERENT_MMAP
	return true;
#else
	return !(tdb->flags & TDB_NOMMAP);
#endif
}

int tdb_mmap(struct tdb_context *tdb)
{
	if (tdb->flags & TDB_INTERNAL)
		return 0;

#ifdef HAVE_MMAP
	if (should_mmap(tdb)) {
		tdb->map_ptr = mmap(NULL, tdb->map_size,
				    PROT_READ|(tdb->read_only? 0:PROT_WRITE),
				    MAP_SHARED|MAP_FILE, tdb->fd,
				    tdb->hdr_ofs);

		/*
		 * NB. When mmap fails it returns MAP_FAILED *NOT* NULL !!!!
		 */

		if (tdb->map_ptr == MAP_FAILED) {
			tdb->map_ptr = NULL;
			TDB_LOG((tdb, TDB_DEBUG_WARNING, "tdb_mmap failed for size %u (%s)\n",
				 tdb->map_size, strerror(errno)));
#ifdef HAVE_INCOHERENT_MMAP
			tdb->ecode = TDB_ERR_IO;
			return -1;
#endif
		}
	} else {
		tdb->map_ptr = NULL;
	}
#else
	tdb->map_ptr = NULL;
#endif
	return 0;
}

/* expand a file.  we prefer to use ftruncate, as that is what posix
  says to use for mmap expansion */
static int tdb_expand_file(struct tdb_context *tdb, tdb_off_t size, tdb_off_t addition)
{
	char buf[8192];
	tdb_off_t new_size;

	if (tdb->read_only || tdb->traverse_read) {
		tdb->ecode = TDB_ERR_RDONLY;
		return -1;
	}

	if (!tdb_add_off_t(size, addition, &new_size)) {
		tdb->ecode = TDB_ERR_OOM;
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "expand_file write "
			"overflow detected current size[%u] addition[%u]!\n",
			(unsigned)size, (unsigned)addition));
		errno = ENOSPC;
		return -1;
	}

	if (tdb_ftruncate(tdb, new_size) == -1) {
		char b = 0;
		ssize_t written = tdb_pwrite(tdb, &b, 1, new_size - 1);
		if (written == 0) {
			/* try once more, potentially revealing errno */
			written = tdb_pwrite(tdb, &b, 1, new_size - 1);
		}
		if (written == 0) {
			/* again - give up, guessing errno */
			errno = ENOSPC;
		}
		if (written != 1) {
			tdb->ecode = TDB_ERR_OOM;
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "expand_file to %u failed (%s)\n",
				 (unsigned)new_size, strerror(errno)));
			return -1;
		}
	}

	/* now fill the file with something. This ensures that the
	   file isn't sparse, which would be very bad if we ran out of
	   disk. This must be done with write, not via mmap */
	memset(buf, TDB_PAD_BYTE, sizeof(buf));
	while (addition) {
		size_t n = addition>sizeof(buf)?sizeof(buf):addition;
		ssize_t written = tdb_pwrite(tdb, buf, n, size);
		if (written == 0) {
			/* prevent infinite loops: try _once_ more */
			written = tdb_pwrite(tdb, buf, n, size);
		}
		if (written == 0) {
			/* give up, trying to provide a useful errno */
			tdb->ecode = TDB_ERR_OOM;
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "expand_file write "
				"returned 0 twice: giving up!\n"));
			errno = ENOSPC;
			return -1;
		}
		if (written == -1) {
			tdb->ecode = TDB_ERR_OOM;
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "expand_file write of "
				 "%u bytes failed (%s)\n", (int)n,
				 strerror(errno)));
			return -1;
		}
		if (written != n) {
			TDB_LOG((tdb, TDB_DEBUG_WARNING, "expand_file: wrote "
				 "only %zu of %zi bytes - retrying\n", written,
				 n));
		}
		addition -= written;
		size += written;
	}
	return 0;
}


/* You need 'size', this tells you how much you should expand by. */
tdb_off_t tdb_expand_adjust(tdb_off_t map_size, tdb_off_t size, int page_size)
{
	tdb_off_t new_size, top_size, increment;
	tdb_off_t max_size = UINT32_MAX - map_size;

	if (size > max_size) {
		/*
		 * We can't round up anymore, just give back
		 * what we're asked for.
		 *
		 * The caller has to take care of the ENOSPC handling.
		 */
		return size;
	}

	/* limit size in order to avoid using up huge amounts of memory for
	 * in memory tdbs if an oddball huge record creeps in */
	if (size > 100 * 1024) {
		increment = size * 2;
	} else {
		increment = size * 100;
	}
	if (increment < size) {
		goto overflow;
	}

	if (!tdb_add_off_t(map_size, increment, &top_size)) {
		goto overflow;
	}

	/* always make room for at least top_size more records, and at
	   least 25% more space. if the DB is smaller than 100MiB,
	   otherwise grow it by 10% only. */
	if (map_size > 100 * 1024 * 1024) {
		new_size = map_size * 1.10;
	} else {
		new_size = map_size * 1.25;
	}
	if (new_size < map_size) {
		goto overflow;
	}

	/* Round the database up to a multiple of the page size */
	new_size = MAX(top_size, new_size);

	if (new_size + page_size < new_size) {
		/* There's a "+" in TDB_ALIGN that might overflow... */
		goto overflow;
	}

	return TDB_ALIGN(new_size, page_size) - map_size;

overflow:
	/*
	 * Somewhere in between we went over 4GB. Make one big jump to
	 * exactly 4GB database size.
	 */
	return max_size;
}

/* expand the database at least size bytes by expanding the underlying
   file and doing the mmap again if necessary */
int tdb_expand(struct tdb_context *tdb, tdb_off_t size)
{
	struct tdb_record rec;
	tdb_off_t offset;
	tdb_off_t new_size;

	if (tdb_lock(tdb, -1, F_WRLCK) == -1) {
		TDB_LOG((tdb, TDB_DEBUG_ERROR, "lock failed in tdb_expand\n"));
		return -1;
	}

	/* must know about any previous expansions by another process */
	tdb->methods->tdb_oob(tdb, tdb->map_size, 1, 1);

	/*
	 * Note: that we don't care about tdb->hdr_ofs != 0 here
	 *
	 * The 4GB limitation is just related to tdb->map_size
	 * and the offset calculation in the records.
	 *
	 * The file on disk can be up to 4GB + tdb->hdr_ofs
	 */
	size = tdb_expand_adjust(tdb->map_size, size, tdb->page_size);

	if (!tdb_add_off_t(tdb->map_size, size, &new_size)) {
		tdb->ecode = TDB_ERR_OOM;
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "tdb_expand "
			"overflow detected current map_size[%u] size[%u]!\n",
			(unsigned)tdb->map_size, (unsigned)size));
		goto fail;
	}

	/* form a new freelist record */
	offset = tdb->map_size;
	memset(&rec,'\0',sizeof(rec));
	rec.rec_len = size - sizeof(rec);

	if (tdb->flags & TDB_INTERNAL) {
		char *new_map_ptr;

		new_map_ptr = (char *)realloc(tdb->map_ptr, new_size);
		if (!new_map_ptr) {
			tdb->ecode = TDB_ERR_OOM;
			goto fail;
		}
		tdb->map_ptr = new_map_ptr;
		tdb->map_size = new_size;
	} else {
		int ret;

		/*
		 * expand the file itself
		 */
		ret = tdb->methods->tdb_expand_file(tdb, tdb->map_size, size);
		if (ret != 0) {
			goto fail;
		}

		/* Explicitly remap: if we're in a transaction, this won't
		 * happen automatically! */
		tdb_munmap(tdb);
		tdb->map_size = new_size;
		if (tdb_mmap(tdb) != 0) {
			goto fail;
		}
	}

	/* link it into the free list */
	if (tdb_free(tdb, offset, &rec) == -1)
		goto fail;

	tdb_unlock(tdb, -1, F_WRLCK);
	return 0;
 fail:
	tdb_unlock(tdb, -1, F_WRLCK);
	return -1;
}

/* read/write a tdb_off_t */
int tdb_ofs_read(struct tdb_context *tdb, tdb_off_t offset, tdb_off_t *d)
{
	return tdb->methods->tdb_read(tdb, offset, (char*)d, sizeof(*d), DOCONV());
}

int tdb_ofs_write(struct tdb_context *tdb, tdb_off_t offset, tdb_off_t *d)
{
	tdb_off_t off = *d;
	return tdb->methods->tdb_write(tdb, offset, CONVERT(off), sizeof(*d));
}


/* read a lump of data, allocating the space for it */
unsigned char *tdb_alloc_read(struct tdb_context *tdb, tdb_off_t offset, tdb_len_t len)
{
	unsigned char *buf;

	/* some systems don't like zero length malloc */

	if (!(buf = (unsigned char *)malloc(len ? len : 1))) {
		/* Ensure ecode is set for log fn. */
		tdb->ecode = TDB_ERR_OOM;
		TDB_LOG((tdb, TDB_DEBUG_ERROR,"tdb_alloc_read malloc failed len=%u (%s)\n",
			   len, strerror(errno)));
		return NULL;
	}
	if (tdb->methods->tdb_read(tdb, offset, buf, len, 0) == -1) {
		SAFE_FREE(buf);
		return NULL;
	}
	return buf;
}

/* Give a piece of tdb data to a parser */

int tdb_parse_data(struct tdb_context *tdb, TDB_DATA key,
		   tdb_off_t offset, tdb_len_t len,
		   int (*parser)(TDB_DATA key, TDB_DATA data,
				 void *private_data),
		   void *private_data)
{
	TDB_DATA data;
	int result;

	data.dsize = len;

	if ((tdb->transaction == NULL) && (tdb->map_ptr != NULL)) {
		/*
		 * Optimize by avoiding the malloc/memcpy/free, point the
		 * parser directly at the mmap area.
		 */
		if (tdb->methods->tdb_oob(tdb, offset, len, 0) != 0) {
			return -1;
		}
		data.dptr = offset + (unsigned char *)tdb->map_ptr;
		return parser(key, data, private_data);
	}

	if (!(data.dptr = tdb_alloc_read(tdb, offset, len))) {
		return -1;
	}

	result = parser(key, data, private_data);
	free(data.dptr);
	return result;
}

/* read/write a record */
int tdb_rec_read(struct tdb_context *tdb, tdb_off_t offset, struct tdb_record *rec)
{
	if (tdb->methods->tdb_read(tdb, offset, rec, sizeof(*rec),DOCONV()) == -1)
		return -1;
	if (TDB_BAD_MAGIC(rec)) {
		/* Ensure ecode is set for log fn. */
		tdb->ecode = TDB_ERR_CORRUPT;
		TDB_LOG((tdb, TDB_DEBUG_FATAL,"tdb_rec_read bad magic 0x%x at offset=%u\n", rec->magic, offset));
		return -1;
	}
	return tdb->methods->tdb_oob(tdb, rec->next, sizeof(*rec), 0);
}

int tdb_rec_write(struct tdb_context *tdb, tdb_off_t offset, struct tdb_record *rec)
{
	struct tdb_record r = *rec;
	return tdb->methods->tdb_write(tdb, offset, CONVERT(r), sizeof(r));
}

static const struct tdb_methods io_methods = {
	tdb_read,
	tdb_write,
	tdb_next_hash_chain,
	tdb_oob,
	tdb_expand_file,
};

/*
  initialise the default methods table
*/
void tdb_io_init(struct tdb_context *tdb)
{
	tdb->methods = &io_methods;
}
