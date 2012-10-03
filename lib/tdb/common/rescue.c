 /*
   Unix SMB/CIFS implementation.

   trivial database library, rescue attempt code.

   Copyright (C) Rusty Russell		   2012

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
#include <assert.h>


struct found {
	tdb_off_t head; /* 0 -> invalid. */
	struct tdb_record rec;
	TDB_DATA key;
	bool in_hash;
	bool in_free;
};

struct found_table {
	/* As an ordered array (by head offset). */
	struct found *arr;
	unsigned int num, max;
};

static bool looks_like_valid_record(struct tdb_context *tdb,
				    tdb_off_t off,
				    const struct tdb_record *rec,
				    TDB_DATA *key)
{
	unsigned int hval;

	if (rec->magic != TDB_MAGIC)
		return false;

	if (rec->key_len + rec->data_len > rec->rec_len)
		return false;

	if (rec->rec_len % TDB_ALIGNMENT)
		return false;

	/* Next pointer must make some sense. */
	if (rec->next > 0 && rec->next < TDB_DATA_START(tdb->header.hash_size))
		return false;

	if (tdb->methods->tdb_oob(tdb, rec->next, sizeof(*rec), 1))
		return false;

	key->dsize = rec->key_len;
	key->dptr = tdb_alloc_read(tdb, off + sizeof(*rec), key->dsize);
	if (!key->dptr)
		return false;

	hval = tdb->hash_fn(key);
	if (hval != rec->full_hash) {
		free(key->dptr);
		return false;
	}

	/* Caller frees up key->dptr */
	return true;
}

static bool add_to_table(struct found_table *found,
			 tdb_off_t off,
			 struct tdb_record *rec,
			 TDB_DATA key)
{
	if (found->num + 1 > found->max) {
		struct found *new;
		found->max = (found->max ? found->max * 2 : 128);
		new = realloc(found->arr, found->max * sizeof(found->arr[0]));
		if (!new)
			return false;
		found->arr = new;
	}

	found->arr[found->num].head = off;
	found->arr[found->num].rec = *rec;
	found->arr[found->num].key = key;
	found->arr[found->num].in_hash = false;
	found->arr[found->num].in_free = false;

	found->num++;
	return true;
}

static bool walk_record(struct tdb_context *tdb,
			const struct found *f,
			void (*walk)(TDB_DATA, TDB_DATA, void *private_data),
			void *private_data)
{
	TDB_DATA data;

	data.dsize = f->rec.data_len;
	data.dptr = tdb_alloc_read(tdb,
				   f->head + sizeof(f->rec) + f->rec.key_len,
				   data.dsize);
	if (!data.dptr) {
		if (tdb->ecode == TDB_ERR_OOM)
			return false;
		/* I/O errors are expected. */
		return true;
	}

	walk(f->key, data, private_data);
	free(data.dptr);
	return true;
}

/* First entry which has offset >= this one. */
static unsigned int find_entry(struct found_table *found, tdb_off_t off)
{
	unsigned int start = 0, end = found->num;

	while (start < end) {
		/* We can't overflow here. */
		unsigned int mid = (start + end) / 2;

		if (off < found->arr[mid].head) {
			end = mid;
		} else if (off > found->arr[mid].head) {
			start = mid + 1;
		} else {
			return mid;
		}
	}

	assert(start == end);
	return end;
}

static void found_in_hashchain(struct found_table *found, tdb_off_t head)
{
	unsigned int match;

	match = find_entry(found, head);
	if (match < found->num && found->arr[match].head == head) {
		found->arr[match].in_hash = true;
	}
}

static void mark_free_area(struct found_table *found, tdb_off_t head,
			   tdb_len_t len)
{
	unsigned int match;

	match = find_entry(found, head);
	/* Mark everything within this free entry. */
	while (match < found->num) {
		if (found->arr[match].head >= head + len) {
			break;
		}
		found->arr[match].in_free = true;
		match++;
	}
}

static int cmp_key(const void *a, const void *b)
{
	const struct found *fa = a, *fb = b;

	if (fa->key.dsize < fb->key.dsize) {
		return -1;
	} else if (fa->key.dsize > fb->key.dsize) {
		return 1;
	}
	return memcmp(fa->key.dptr, fb->key.dptr, fa->key.dsize);
}

static bool key_eq(TDB_DATA a, TDB_DATA b)
{
	return a.dsize == b.dsize
		&& memcmp(a.dptr, b.dptr, a.dsize) == 0;
}

static void free_table(struct found_table *found)
{
	unsigned int i;

	for (i = 0; i < found->num; i++) {
		free(found->arr[i].key.dptr);
	}
	free(found->arr);
}

static void logging_suppressed(struct tdb_context *tdb,
			       enum tdb_debug_level level, const char *fmt, ...)
{
}

_PUBLIC_ int tdb_rescue(struct tdb_context *tdb,
			void (*walk)(TDB_DATA, TDB_DATA, void *private_data),
			void *private_data)
{
	struct found_table found = { NULL, 0, 0 };
	tdb_off_t h, off, i;
	tdb_log_func oldlog = tdb->log.log_fn;
	struct tdb_record rec;
	TDB_DATA key;
	bool locked;

	/* Read-only databases use no locking at all: it's best-effort.
	 * We may have a write lock already, so skip that case too. */
	if (tdb->read_only || tdb->allrecord_lock.count != 0) {
		locked = false;
	} else {
		if (tdb_lockall_read(tdb) == -1)
			return -1;
		locked = true;
	}

	/* Make sure we know true size of the underlying file. */
	tdb->methods->tdb_oob(tdb, tdb->map_size, 1, 1);

	/* Suppress logging, since we anticipate errors. */
	tdb->log.log_fn = logging_suppressed;

	/* Now walk entire db looking for records. */
	for (off = TDB_DATA_START(tdb->header.hash_size);
	     off < tdb->map_size;
	     off += TDB_ALIGNMENT) {
		if (tdb->methods->tdb_read(tdb, off, &rec, sizeof(rec),
					   DOCONV()) == -1)
			continue;

		if (looks_like_valid_record(tdb, off, &rec, &key)) {
			if (!add_to_table(&found, off, &rec, key)) {
				goto oom;
			}
		}
	}

	/* Walk hash chains to positive vet. */
	for (h = 0; h < 1+tdb->header.hash_size; h++) {
		bool slow_chase = false;
		tdb_off_t slow_off = FREELIST_TOP + h*sizeof(tdb_off_t);

		if (tdb_ofs_read(tdb, FREELIST_TOP + h*sizeof(tdb_off_t),
				 &off) == -1)
			continue;

		while (off && off != slow_off) {
			if (tdb->methods->tdb_read(tdb, off, &rec, sizeof(rec),
						   DOCONV()) != 0) {
				break;
			}

			/* 0 is the free list, rest are hash chains. */
			if (h == 0) {
				/* Don't mark garbage as free. */
				if (rec.magic != TDB_FREE_MAGIC) {
					break;
				}
				mark_free_area(&found, off,
					       sizeof(rec) + rec.rec_len);
			} else {
				found_in_hashchain(&found, off);
			}

			off = rec.next;

			/* Loop detection using second pointer at half-speed */
			if (slow_chase) {
				/* First entry happens to be next ptr */
				tdb_ofs_read(tdb, slow_off, &slow_off);
			}
			slow_chase = !slow_chase;
		}
	}

	/* Recovery area: must be marked as free, since it often has old
	 * records in there! */
	if (tdb_ofs_read(tdb, TDB_RECOVERY_HEAD, &off) == 0 && off != 0) {
		if (tdb->methods->tdb_read(tdb, off, &rec, sizeof(rec),
					   DOCONV()) == 0) {
			mark_free_area(&found, off, sizeof(rec) + rec.rec_len);
		}
	}

	/* Now sort by key! */
	qsort(found.arr, found.num, sizeof(found.arr[0]), cmp_key);

	for (i = 0; i < found.num; ) {
		unsigned int num, num_in_hash = 0;

		/* How many are identical? */
		for (num = 0; num < found.num - i; num++) {
			if (!key_eq(found.arr[i].key, found.arr[i+num].key)) {
				break;
			}
			if (found.arr[i+num].in_hash) {
				if (!walk_record(tdb, &found.arr[i+num],
						 walk, private_data))
					goto oom;
				num_in_hash++;
			}
		}
		assert(num);

		/* If none were in the hash, we print any not in free list. */
		if (num_in_hash == 0) {
			unsigned int j;

			for (j = i; j < i + num; j++) {
				if (!found.arr[j].in_free) {
					if (!walk_record(tdb, &found.arr[j],
							 walk, private_data))
						goto oom;
				}
			}
		}

		i += num;
	}

	tdb->log.log_fn = oldlog;
	if (locked) {
		tdb_unlockall_read(tdb);
	}
	return 0;

oom:
	tdb->log.log_fn = oldlog;
	tdb->ecode = TDB_ERR_OOM;
	TDB_LOG((tdb, TDB_DEBUG_ERROR, "tdb_rescue: failed allocating\n"));
	free_table(&found);
	if (locked) {
		tdb_unlockall_read(tdb);
	}
	return -1;
}
