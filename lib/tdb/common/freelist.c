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

/* read a freelist record and check for simple errors */
int tdb_rec_free_read(struct tdb_context *tdb, tdb_off_t off, struct tdb_record *rec)
{
	if (tdb->methods->tdb_read(tdb, off, rec, sizeof(*rec),DOCONV()) == -1)
		return -1;

	if (rec->magic == TDB_MAGIC) {
		/* this happens when a app is showdown while deleting a record - we should
		   not completely fail when this happens */
		TDB_LOG((tdb, TDB_DEBUG_WARNING, "tdb_rec_free_read non-free magic 0x%x at offset=%u - fixing\n",
			 rec->magic, off));
		rec->magic = TDB_FREE_MAGIC;
		if (tdb_rec_write(tdb, off, rec) == -1)
			return -1;
	}

	if (rec->magic != TDB_FREE_MAGIC) {
		/* Ensure ecode is set for log fn. */
		tdb->ecode = TDB_ERR_CORRUPT;
		TDB_LOG((tdb, TDB_DEBUG_WARNING, "tdb_rec_free_read bad magic 0x%x at offset=%u\n",
			   rec->magic, off));
		return -1;
	}
	if (tdb_oob(tdb, rec->next, sizeof(*rec), 0) != 0)
		return -1;
	return 0;
}

/* update a record tailer (must hold allocation lock) */
static int update_tailer(struct tdb_context *tdb, tdb_off_t offset,
			 const struct tdb_record *rec)
{
	tdb_off_t totalsize;

	/* Offset of tailer from record header */
	totalsize = sizeof(*rec) + rec->rec_len;
	return tdb_ofs_write(tdb, offset + totalsize - sizeof(tdb_off_t),
			 &totalsize);
}

/**
 * Read the record directly on the left.
 * Fail if there is no record on the left.
 */
static int read_record_on_left(struct tdb_context *tdb, tdb_off_t rec_ptr,
			       tdb_off_t *left_p,
			       struct tdb_record *left_r)
{
	tdb_off_t left_ptr;
	tdb_off_t left_size;
	struct tdb_record left_rec;
	int ret;

	left_ptr = rec_ptr - sizeof(tdb_off_t);

	if (left_ptr <= TDB_DATA_START(tdb->hash_size)) {
		/* no record on the left */
		return -1;
	}

	/* Read in tailer and jump back to header */
	ret = tdb_ofs_read(tdb, left_ptr, &left_size);
	if (ret == -1) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL,
			"tdb_free: left offset read failed at %u\n", left_ptr));
		return -1;
	}

	/* it could be uninitialised data */
	if (left_size == 0 || left_size == TDB_PAD_U32) {
		return -1;
	}

	if (left_size > rec_ptr) {
		return -1;
	}

	left_ptr = rec_ptr - left_size;

	if (left_ptr < TDB_DATA_START(tdb->hash_size)) {
		return -1;
	}

	/* Now read in the left record */
	ret = tdb->methods->tdb_read(tdb, left_ptr, &left_rec,
				     sizeof(left_rec), DOCONV());
	if (ret == -1) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL,
			 "tdb_free: left read failed at %u (%u)\n",
			 left_ptr, left_size));
		return -1;
	}

	*left_p = left_ptr;
	*left_r = left_rec;

	return 0;
}

/**
 * Merge new freelist record with the direct left neighbour.
 * This assumes that left_rec represents the record
 * directly to the left of right_rec and that this is
 * a freelist record.
 */
static int merge_with_left_record(struct tdb_context *tdb,
				  tdb_off_t left_ptr,
				  struct tdb_record *left_rec,
				  struct tdb_record *right_rec)
{
	int ret;

	left_rec->rec_len += sizeof(*right_rec) + right_rec->rec_len;

	ret = tdb_rec_write(tdb, left_ptr, left_rec);
	if (ret == -1) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL,
			 "merge_with_left_record: update_left failed at %u\n",
			 left_ptr));
		return -1;
	}

	ret = update_tailer(tdb, left_ptr, left_rec);
	if (ret == -1) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL,
			 "merge_with_left_record: update_tailer failed at %u\n",
			 left_ptr));
		return -1;
	}

	return 0;
}

/**
 * Check whether the record left of a given freelist record is
 * also a freelist record, and if so, merge the two records.
 *
 * Return code:
 *  -1 upon error
 *   0 if left was not a free record
 *   1 if left was free and successfully merged.
 *
 * The current record is handed in with pointer and fully read record.
 *
 * The left record pointer and struct can be retrieved as result
 * in lp and lr;
 */
static int check_merge_with_left_record(struct tdb_context *tdb,
					tdb_off_t rec_ptr,
					struct tdb_record *rec,
					tdb_off_t *lp,
					struct tdb_record *lr)
{
	tdb_off_t left_ptr;
	struct tdb_record left_rec;
	int ret;

	ret = read_record_on_left(tdb, rec_ptr, &left_ptr, &left_rec);
	if (ret != 0) {
		return 0;
	}

	if (left_rec.magic != TDB_FREE_MAGIC) {
		return 0;
	}

	/* It's free - expand to include it. */
	ret = merge_with_left_record(tdb, left_ptr, &left_rec, rec);
	if (ret != 0) {
		return -1;
	}

	if (lp != NULL) {
		*lp = left_ptr;
	}

	if (lr != NULL) {
		*lr = left_rec;
	}

	return 1;
}

/**
 * Check whether the record left of a given freelist record is
 * also a freelist record, and if so, merge the two records.
 *
 * Return code:
 *  -1 upon error
 *   0 if left was not a free record
 *   1 if left was free and successfully merged.
 *
 * In this variant, the input record is specified just as the pointer
 * and is read from the database if needed.
 *
 * next_ptr will contain the original record's next pointer after
 * successful merging (which will be lost after merging), so that
 * the caller can update the last pointer.
 */
static int check_merge_ptr_with_left_record(struct tdb_context *tdb,
					    tdb_off_t rec_ptr,
					    tdb_off_t *next_ptr)
{
	tdb_off_t left_ptr;
	struct tdb_record rec, left_rec;
	int ret;

	ret = read_record_on_left(tdb, rec_ptr, &left_ptr, &left_rec);
	if (ret != 0) {
		return 0;
	}

	if (left_rec.magic != TDB_FREE_MAGIC) {
		return 0;
	}

	/* It's free - expand to include it. */

	ret = tdb->methods->tdb_read(tdb, rec_ptr, &rec,
				     sizeof(rec), DOCONV());
	if (ret != 0) {
		return -1;
	}

	ret = merge_with_left_record(tdb, left_ptr, &left_rec, &rec);
	if (ret != 0) {
		return -1;
	}

	if (next_ptr != NULL) {
		*next_ptr = rec.next;
	}

	return 1;
}

/**
 * Add an element into the freelist.
 *
 * We merge the new record into the left record if it is also a
 * free record, but not with the right one. This makes the
 * operation O(1) instead of O(n): merging with the right record
 * requires a traverse of the freelist to find the previous
 * record in the free list.
 *
 * This prevents db traverses from being O(n^2) after a lot of deletes.
 */
int tdb_free(struct tdb_context *tdb, tdb_off_t offset, struct tdb_record *rec)
{
	int ret;

	/* Allocation and tailer lock */
	if (tdb_lock(tdb, -1, F_WRLCK) != 0)
		return -1;

	/* set an initial tailer, so if we fail we don't leave a bogus record */
	if (update_tailer(tdb, offset, rec) != 0) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "tdb_free: update_tailer failed!\n"));
		goto fail;
	}

	ret = check_merge_with_left_record(tdb, offset, rec, NULL, NULL);
	if (ret == -1) {
		goto fail;
	}
	if (ret == 1) {
		/* merged */
		goto done;
	}

	/* Nothing to merge, prepend to free list */

	rec->magic = TDB_FREE_MAGIC;

	if (tdb_ofs_read(tdb, FREELIST_TOP, &rec->next) == -1 ||
	    tdb_rec_write(tdb, offset, rec) == -1 ||
	    tdb_ofs_write(tdb, FREELIST_TOP, &offset) == -1) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "tdb_free record write failed at offset=%u\n", offset));
		goto fail;
	}

done:
	/* And we're done. */
	tdb_unlock(tdb, -1, F_WRLCK);
	return 0;

 fail:
	tdb_unlock(tdb, -1, F_WRLCK);
	return -1;
}



/*
   the core of tdb_allocate - called when we have decided which
   free list entry to use

   Note that we try to allocate by grabbing data from the end of an existing record,
   not the beginning. This is so the left merge in a free is more likely to be
   able to free up the record without fragmentation
 */
static tdb_off_t tdb_allocate_ofs(struct tdb_context *tdb,
				  tdb_len_t length, tdb_off_t rec_ptr,
				  struct tdb_record *rec, tdb_off_t last_ptr)
{
#define MIN_REC_SIZE (sizeof(struct tdb_record) + sizeof(tdb_off_t) + 8)

	if (rec->rec_len < length + MIN_REC_SIZE) {
		/* we have to grab the whole record */

		/* unlink it from the previous record */
		if (tdb_ofs_write(tdb, last_ptr, &rec->next) == -1) {
			return 0;
		}

		/* mark it not free */
		rec->magic = TDB_MAGIC;
		if (tdb_rec_write(tdb, rec_ptr, rec) == -1) {
			return 0;
		}
		return rec_ptr;
	}

	/* we're going to just shorten the existing record */
	rec->rec_len -= (length + sizeof(*rec));
	if (tdb_rec_write(tdb, rec_ptr, rec) == -1) {
		return 0;
	}
	if (update_tailer(tdb, rec_ptr, rec) == -1) {
		return 0;
	}

	/* and setup the new record */
	rec_ptr += sizeof(*rec) + rec->rec_len;

	memset(rec, '\0', sizeof(*rec));
	rec->rec_len = length;
	rec->magic = TDB_MAGIC;

	if (tdb_rec_write(tdb, rec_ptr, rec) == -1) {
		return 0;
	}

	if (update_tailer(tdb, rec_ptr, rec) == -1) {
		return 0;
	}

	return rec_ptr;
}

/* allocate some space from the free list. The offset returned points
   to a unconnected tdb_record within the database with room for at
   least length bytes of total data

   0 is returned if the space could not be allocated
 */
static tdb_off_t tdb_allocate_from_freelist(
	struct tdb_context *tdb, tdb_len_t length, struct tdb_record *rec)
{
	tdb_off_t rec_ptr, last_ptr, newrec_ptr;
	struct tdb_chainwalk_ctx chainwalk;
	bool modified;
	struct {
		tdb_off_t rec_ptr, last_ptr;
		tdb_len_t rec_len;
	} bestfit;
	float multiplier = 1.0;
	bool merge_created_candidate;

	/* over-allocate to reduce fragmentation */
	length *= 1.25;

	/* Extra bytes required for tailer */
	length += sizeof(tdb_off_t);
	length = TDB_ALIGN(length, TDB_ALIGNMENT);

 again:
	merge_created_candidate = false;
	last_ptr = FREELIST_TOP;

	/* read in the freelist top */
	if (tdb_ofs_read(tdb, FREELIST_TOP, &rec_ptr) == -1)
		return 0;

	modified = false;
	tdb_chainwalk_init(&chainwalk, rec_ptr);

	bestfit.rec_ptr = 0;
	bestfit.last_ptr = 0;
	bestfit.rec_len = 0;

	/*
	   this is a best fit allocation strategy. Originally we used
	   a first fit strategy, but it suffered from massive fragmentation
	   issues when faced with a slowly increasing record size.
	 */
	while (rec_ptr) {
		int ret;
		tdb_off_t left_ptr;
		struct tdb_record left_rec;

		if (tdb_rec_free_read(tdb, rec_ptr, rec) == -1) {
			return 0;
		}

		ret = check_merge_with_left_record(tdb, rec_ptr, rec,
						   &left_ptr, &left_rec);
		if (ret == -1) {
			return 0;
		}
		if (ret == 1) {
			/* merged */
			rec_ptr = rec->next;
			ret = tdb_ofs_write(tdb, last_ptr, &rec->next);
			if (ret == -1) {
				return 0;
			}

			/*
			 * We have merged the current record into the left
			 * neighbour. So our traverse of the freelist will
			 * skip it and consider the next record in the chain.
			 *
			 * But the enlarged left neighbour may be a candidate.
			 * If it is, we can not directly use it, though.
			 * The only thing we can do and have to do here is to
			 * update the current best fit size in the chain if the
			 * current best fit is the left record. (By that we may
			 * worsen the best fit we already had, bit this is not a
			 * problem.)
			 *
			 * If the current best fit is not the left record,
			 * all we can do is remember the fact that a merge
			 * created a new candidate so that we can trigger
			 * a second walk of the freelist if at the end of
			 * the first walk we have not found any fit.
			 * This way we can avoid expanding the database.
			 */

			if (bestfit.rec_ptr == left_ptr) {
				bestfit.rec_len = left_rec.rec_len;
			}

			if (left_rec.rec_len > length) {
				merge_created_candidate = true;
			}

			modified = true;

			continue;
		}

		if (rec->rec_len >= length) {
			if (bestfit.rec_ptr == 0 ||
			    rec->rec_len < bestfit.rec_len) {
				bestfit.rec_len = rec->rec_len;
				bestfit.rec_ptr = rec_ptr;
				bestfit.last_ptr = last_ptr;
			}
		}

		/* move to the next record */
		last_ptr = rec_ptr;
		rec_ptr = rec->next;

		if (!modified) {
			bool ok;
			ok = tdb_chainwalk_check(tdb, &chainwalk, rec_ptr);
			if (!ok) {
				return 0;
			}
		}

		/* if we've found a record that is big enough, then
		   stop searching if its also not too big. The
		   definition of 'too big' changes as we scan
		   through */
		if (bestfit.rec_len > 0 &&
		    bestfit.rec_len < length * multiplier) {
			break;
		}

		/* this multiplier means we only extremely rarely
		   search more than 50 or so records. At 50 records we
		   accept records up to 11 times larger than what we
		   want */
		multiplier *= 1.05;
	}

	if (bestfit.rec_ptr != 0) {
		if (tdb_rec_free_read(tdb, bestfit.rec_ptr, rec) == -1) {
			return 0;
		}

		newrec_ptr = tdb_allocate_ofs(tdb, length, bestfit.rec_ptr,
					      rec, bestfit.last_ptr);
		return newrec_ptr;
	}

	if (merge_created_candidate) {
		goto again;
	}

	/* we didn't find enough space. See if we can expand the
	   database and if we can then try again */
	if (tdb_expand(tdb, length + sizeof(*rec)) == 0)
		goto again;

	return 0;
}

static bool tdb_alloc_dead(
	struct tdb_context *tdb, int hash, tdb_len_t length,
	tdb_off_t *rec_ptr, struct tdb_record *rec)
{
	tdb_off_t last_ptr;

	*rec_ptr = tdb_find_dead(tdb, hash, rec, length, &last_ptr);
	if (*rec_ptr == 0) {
		return false;
	}
	/*
	 * Unlink the record from the hash chain, it's about to be moved into
	 * another one.
	 */
	return (tdb_ofs_write(tdb, last_ptr, &rec->next) == 0);
}

static void tdb_purge_dead(struct tdb_context *tdb, uint32_t hash)
{
	int max_dead_records = tdb->max_dead_records;

	tdb->max_dead_records = 0;

	tdb_trim_dead(tdb, hash);

	tdb->max_dead_records = max_dead_records;
}

/*
 * Chain "hash" is assumed to be locked
 */

tdb_off_t tdb_allocate(struct tdb_context *tdb, int hash, tdb_len_t length,
		       struct tdb_record *rec)
{
	tdb_off_t ret;
	uint32_t i;

	if (tdb->max_dead_records == 0) {
		/*
		 * No dead records to expect anywhere. Do the blocking
		 * freelist lock without trying to steal from others
		 */
		goto blocking_freelist_allocate;
	}

	/*
	 * The following loop tries to get the freelist lock nonblocking. If
	 * it gets the lock, allocate from there. If the freelist is busy,
	 * instead of waiting we try to steal dead records from other hash
	 * chains.
	 *
	 * Be aware that we do nonblocking locks on the other hash chains as
	 * well and fail gracefully. This way we avoid deadlocks (we block two
	 * hash chains, something which is pretty bad normally)
	 */

	for (i=0; i<tdb->hash_size; i++) {

		int list;

		list = BUCKET(hash+i);

		if (tdb_lock_nonblock(tdb, list, F_WRLCK) == 0) {
			bool got_dead;

			got_dead = tdb_alloc_dead(tdb, list, length, &ret, rec);
			tdb_unlock(tdb, list, F_WRLCK);

			if (got_dead) {
				return ret;
			}
		}

		if (tdb_lock_nonblock(tdb, -1, F_WRLCK) == 0) {
			/*
			 * Under the freelist lock take the chance to give
			 * back our dead records.
			 */
			tdb_purge_dead(tdb, hash);

			ret = tdb_allocate_from_freelist(tdb, length, rec);
			tdb_unlock(tdb, -1, F_WRLCK);
			return ret;
		}
	}

blocking_freelist_allocate:

	if (tdb_lock(tdb, -1, F_WRLCK) == -1) {
		return 0;
	}
	/*
	 * Dead records can happen even if max_dead_records==0, they
	 * are older than the max_dead_records concept: They happen if
	 * tdb_delete happens concurrently with a traverse.
	 */
	tdb_purge_dead(tdb, hash);
	ret = tdb_allocate_from_freelist(tdb, length, rec);
	tdb_unlock(tdb, -1, F_WRLCK);
	return ret;
}

/**
 * Merge adjacent records in the freelist.
 */
static int tdb_freelist_merge_adjacent(struct tdb_context *tdb,
				       int *count_records, int *count_merged)
{
	tdb_off_t cur, next;
	int count = 0;
	int merged = 0;
	int ret;

	ret = tdb_lock(tdb, -1, F_RDLCK);
	if (ret == -1) {
		return -1;
	}

	cur = FREELIST_TOP;
	while (tdb_ofs_read(tdb, cur, &next) == 0 && next != 0) {
		tdb_off_t next2;

		count++;

		ret = check_merge_ptr_with_left_record(tdb, next, &next2);
		if (ret == -1) {
			goto done;
		}
		if (ret == 1) {
			/*
			 * merged:
			 * now let cur->next point to next2 instead of next
			 */

			ret = tdb_ofs_write(tdb, cur, &next2);
			if (ret != 0) {
				goto done;
			}

			next = next2;
			merged++;
		}

		cur = next;
	}

	if (count_records != NULL) {
		*count_records = count;
	}

	if (count_merged != NULL) {
		*count_merged = merged;
	}

	ret = 0;

done:
	tdb_unlock(tdb, -1, F_RDLCK);
	return ret;
}

/**
 * return the size of the freelist - no merging done
 */
static int tdb_freelist_size_no_merge(struct tdb_context *tdb)
{
	tdb_off_t ptr;
	int count=0;

	if (tdb_lock(tdb, -1, F_RDLCK) == -1) {
		return -1;
	}

	ptr = FREELIST_TOP;
	while (tdb_ofs_read(tdb, ptr, &ptr) == 0 && ptr != 0) {
		count++;
	}

	tdb_unlock(tdb, -1, F_RDLCK);
	return count;
}

/**
 * return the size of the freelist - used to decide if we should repack
 *
 * As a side effect, adjacent records are merged unless the
 * database is read-only, in order to reduce the fragmentation
 * without repacking.
 */
_PUBLIC_ int tdb_freelist_size(struct tdb_context *tdb)
{

	int count = 0;

	if (tdb->read_only) {
		count = tdb_freelist_size_no_merge(tdb);
	} else {
		int ret;
		ret = tdb_freelist_merge_adjacent(tdb, &count, NULL);
		if (ret != 0) {
			return -1;
		}
	}

	return count;
}
