/*
   Unix SMB/CIFS implementation.
   byte range locking code
   Updated to handle range splits/merges.

   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison 1992-2000

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

/* This module implements a tdb based byte range locking service,
   replacing the fcntl() based byte range locking previously
   used. This allows us to provide the same semantics as NT */

#include "includes.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "locking/proto.h"
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "serverid.h"
#include "messages.h"
#include "util_tdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

#define ZERO_ZERO 0

/* The open brlock.tdb database. */

static struct db_context *brlock_db;

struct byte_range_lock {
	struct files_struct *fsp;
	TALLOC_CTX *req_mem_ctx;
	const struct GUID *req_guid;
	unsigned int num_locks;
	bool modified;
	struct lock_struct *lock_data;
	struct db_record *record;
};

/****************************************************************************
 Debug info at level 10 for lock struct.
****************************************************************************/

static void print_lock_struct(unsigned int i, const struct lock_struct *pls)
{
	struct server_id_buf tmp;

	DBG_DEBUG("[%u]: smblctx = %"PRIu64", tid = %"PRIu32", pid = %s, "
		  "start = %"PRIu64", size = %"PRIu64", fnum = %"PRIu64", "
		  "%s %s\n",
		  i,
		  pls->context.smblctx,
		  pls->context.tid,
		  server_id_str_buf(pls->context.pid, &tmp),
		  pls->start,
		  pls->size,
		  pls->fnum,
		  lock_type_name(pls->lock_type),
		  lock_flav_name(pls->lock_flav));
}

unsigned int brl_num_locks(const struct byte_range_lock *brl)
{
	return brl->num_locks;
}

struct files_struct *brl_fsp(struct byte_range_lock *brl)
{
	return brl->fsp;
}

TALLOC_CTX *brl_req_mem_ctx(const struct byte_range_lock *brl)
{
	if (brl->req_mem_ctx == NULL) {
		return talloc_get_type_abort(brl, struct byte_range_lock);
	}

	return brl->req_mem_ctx;
}

const struct GUID *brl_req_guid(const struct byte_range_lock *brl)
{
	if (brl->req_guid == NULL) {
		static const struct GUID brl_zero_req_guid;
		return &brl_zero_req_guid;
	}

	return brl->req_guid;
}

/****************************************************************************
 See if two locking contexts are equal.
****************************************************************************/

static bool brl_same_context(const struct lock_context *ctx1,
			     const struct lock_context *ctx2)
{
	return (server_id_equal(&ctx1->pid, &ctx2->pid) &&
		(ctx1->smblctx == ctx2->smblctx) &&
		(ctx1->tid == ctx2->tid));
}

bool byte_range_valid(uint64_t ofs, uint64_t len)
{
	uint64_t max_len = UINT64_MAX - ofs;
	uint64_t effective_len;

	/*
	 * [MS-FSA] specifies this:
	 *
	 * If (((FileOffset + Length - 1) < FileOffset) && Length != 0) {
	 *   return STATUS_INVALID_LOCK_RANGE
	 * }
	 *
	 * We avoid integer wrapping and calculate
	 * max and effective len instead.
	 */

	if (len == 0) {
		return true;
	}

	effective_len = len - 1;
	if (effective_len <= max_len) {
		return true;
	}

	return false;
}

bool byte_range_overlap(uint64_t ofs1,
			uint64_t len1,
			uint64_t ofs2,
			uint64_t len2)
{
	uint64_t last1;
	uint64_t last2;
	bool valid;

	/*
	 * This is based on [MS-FSA] 2.1.4.10
	 * Algorithm for Determining If a Range Access
	 * Conflicts with Byte-Range Locks
	 */

	/*
	 * The {0, 0} range doesn't conflict with any byte-range lock
	 */
	if (ofs1 == 0 && len1 == 0) {
		return false;
	}
	if (ofs2 == 0 && len2 == 0) {
		return false;
	}

	/*
	 * The caller should have checked that the ranges are
	 * valid. But currently we gracefully handle
	 * the overflow of a read/write check.
	 */
	valid = byte_range_valid(ofs1, len1);
	if (valid) {
		last1 = ofs1 + len1 - 1;
	} else {
		last1 = UINT64_MAX;
	}
	valid = byte_range_valid(ofs2, len2);
	if (valid) {
		last2 = ofs2 + len2 - 1;
	} else {
		last2 = UINT64_MAX;
	}

	/*
	 * If one range starts after the last
	 * byte of the other range there's
	 * no conflict.
	 */
	if (ofs1 > last2) {
		return false;
	}
	if (ofs2 > last1) {
		return false;
	}

	return true;
}

/****************************************************************************
 See if lck1 and lck2 overlap.
****************************************************************************/

static bool brl_overlap(const struct lock_struct *lck1,
                        const struct lock_struct *lck2)
{
	return byte_range_overlap(lck1->start,
				  lck1->size,
				  lck2->start,
				  lck2->size);
}

/****************************************************************************
 See if lock2 can be added when lock1 is in place.
****************************************************************************/

static bool brl_conflict(const struct lock_struct *lck1,
			 const struct lock_struct *lck2)
{
	/* Read locks never conflict. */
	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) {
		return False;
	}

	/* A READ lock can stack on top of a WRITE lock if they have the same
	 * context & fnum. */
	if (lck1->lock_type == WRITE_LOCK && lck2->lock_type == READ_LOCK &&
	    brl_same_context(&lck1->context, &lck2->context) &&
	    lck1->fnum == lck2->fnum) {
		return False;
	}

	return brl_overlap(lck1, lck2);
}

/****************************************************************************
 See if lock2 can be added when lock1 is in place - when both locks are POSIX
 flavour. POSIX locks ignore fnum - they only care about dev/ino which we
 know already match.
****************************************************************************/

static bool brl_conflict_posix(const struct lock_struct *lck1,
			 	const struct lock_struct *lck2)
{
#if defined(DEVELOPER)
	SMB_ASSERT(lck1->lock_flav == POSIX_LOCK);
	SMB_ASSERT(lck2->lock_flav == POSIX_LOCK);
#endif

	/* Read locks never conflict. */
	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) {
		return False;
	}

	/* Locks on the same context don't conflict. Ignore fnum. */
	if (brl_same_context(&lck1->context, &lck2->context)) {
		return False;
	}

	/* One is read, the other write, or the context is different,
	   do they overlap ? */
	return brl_overlap(lck1, lck2);
}

#if ZERO_ZERO
static bool brl_conflict1(const struct lock_struct *lck1,
			 const struct lock_struct *lck2)
{
	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) {
		return False;
	}

	if (brl_same_context(&lck1->context, &lck2->context) &&
	    lck2->lock_type == READ_LOCK && lck1->fnum == lck2->fnum) {
		return False;
	}

	if (lck2->start == 0 && lck2->size == 0 && lck1->size != 0) {
		return True;
	}

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size)) {
		return False;
	}

	return True;
}
#endif

/****************************************************************************
 Check to see if this lock conflicts, but ignore our own locks on the
 same fnum only. This is the read/write lock check code path.
 This is never used in the POSIX lock case.
****************************************************************************/

static bool brl_conflict_other(const struct lock_struct *lock,
			       const struct lock_struct *rw_probe)
{
	if (lock->lock_type == READ_LOCK && rw_probe->lock_type == READ_LOCK) {
		return False;
	}

	if (lock->lock_flav == POSIX_LOCK &&
	    rw_probe->lock_flav == POSIX_LOCK) {
		/*
		 * POSIX flavour locks never conflict here - this is only called
		 * in the read/write path.
		 */
		return False;
	}

	if (!brl_overlap(lock, rw_probe)) {
		/*
		 * I/O can only conflict when overlapping a lock, thus let it
		 * pass
		 */
		return false;
	}

	if (!brl_same_context(&lock->context, &rw_probe->context)) {
		/*
		 * Different process, conflict
		 */
		return true;
	}

	if (lock->fnum != rw_probe->fnum) {
		/*
		 * Different file handle, conflict
		 */
		return true;
	}

	if ((lock->lock_type == READ_LOCK) &&
	    (rw_probe->lock_type == WRITE_LOCK)) {
		/*
		 * Incoming WRITE locks conflict with existing READ locks even
		 * if the context is the same. JRA. See LOCKTEST7 in
		 * smbtorture.
		 */
		return true;
	}

	/*
	 * I/O request compatible with existing lock, let it pass without
	 * conflict
	 */

	return false;
}

/****************************************************************************
 Open up the brlock.tdb database.
****************************************************************************/

void brl_init(bool read_only)
{
	int tdb_flags;
	char *db_path;

	if (brlock_db) {
		return;
	}

	tdb_flags =
		TDB_DEFAULT|
		TDB_VOLATILE|
		TDB_CLEAR_IF_FIRST|
		TDB_INCOMPATIBLE_HASH|
		TDB_SEQNUM;

	db_path = lock_path(talloc_tos(), "brlock.tdb");
	if (db_path == NULL) {
		DEBUG(0, ("out of memory!\n"));
		return;
	}

	brlock_db = db_open(NULL, db_path,
			    SMB_OPEN_DATABASE_TDB_HASH_SIZE, tdb_flags,
			    read_only?O_RDONLY:(O_RDWR|O_CREAT), 0644,
			    DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE);
	if (!brlock_db) {
		DEBUG(0,("Failed to open byte range locking database %s\n",
			 db_path));
		TALLOC_FREE(db_path);
		return;
	}
	TALLOC_FREE(db_path);
}

/****************************************************************************
 Close down the brlock.tdb database.
****************************************************************************/

void brl_shutdown(void)
{
	TALLOC_FREE(brlock_db);
}

#if ZERO_ZERO
/****************************************************************************
 Compare two locks for sorting.
****************************************************************************/

static int lock_compare(const struct lock_struct *lck1,
			 const struct lock_struct *lck2)
{
	if (lck1->start != lck2->start) {
		return (lck1->start - lck2->start);
	}
	if (lck2->size != lck1->size) {
		return ((int)lck1->size - (int)lck2->size);
	}
	return 0;
}
#endif

/****************************************************************************
 Lock a range of bytes - Windows lock semantics.
****************************************************************************/

NTSTATUS brl_lock_windows_default(struct byte_range_lock *br_lck,
				  struct lock_struct *plock)
{
	unsigned int i;
	files_struct *fsp = br_lck->fsp;
	struct lock_struct *locks = br_lck->lock_data;
	NTSTATUS status;
	bool valid;

	SMB_ASSERT(plock->lock_type != UNLOCK_LOCK);

	valid = byte_range_valid(plock->start, plock->size);
	if (!valid) {
		return NT_STATUS_INVALID_LOCK_RANGE;
	}

	for (i=0; i < br_lck->num_locks; i++) {
		/* Do any Windows or POSIX locks conflict ? */
		if (brl_conflict(&locks[i], plock)) {
			if (!serverid_exists(&locks[i].context.pid)) {
				locks[i].context.pid.pid = 0;
				br_lck->modified = true;
				continue;
			}
			/* Remember who blocked us. */
			plock->context.smblctx = locks[i].context.smblctx;
			return NT_STATUS_LOCK_NOT_GRANTED;
		}
#if ZERO_ZERO
		if (plock->start == 0 && plock->size == 0 &&
				locks[i].size == 0) {
			break;
		}
#endif
	}

	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_WINDOWS_BRL);

	/* We can get the Windows lock, now see if it needs to
	   be mapped into a lower level POSIX one, and if so can
	   we get it ? */

	if (lp_posix_locking(fsp->conn->params)) {
		int errno_ret;
		if (!set_posix_lock_windows_flavour(fsp,
				plock->start,
				plock->size,
				plock->lock_type,
				&plock->context,
				locks,
				br_lck->num_locks,
				&errno_ret)) {

			/* We don't know who blocked us. */
			plock->context.smblctx = 0xFFFFFFFFFFFFFFFFLL;

			if (errno_ret == EACCES || errno_ret == EAGAIN) {
				status = NT_STATUS_LOCK_NOT_GRANTED;
				goto fail;
			} else {
				status = map_nt_error_from_unix(errno);
				goto fail;
			}
		}
	}

	/* no conflicts - add it to the list of locks */
	locks = talloc_realloc(br_lck, locks, struct lock_struct,
			       (br_lck->num_locks + 1));
	if (!locks) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	memcpy(&locks[br_lck->num_locks], plock, sizeof(struct lock_struct));
	br_lck->num_locks += 1;
	br_lck->lock_data = locks;
	br_lck->modified = True;

	return NT_STATUS_OK;
 fail:
	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_WINDOWS_BRL);
	return status;
}

/****************************************************************************
 Cope with POSIX range splits and merges.
****************************************************************************/

static unsigned int brlock_posix_split_merge(struct lock_struct *lck_arr,	/* Output array. */
						struct lock_struct *ex,		/* existing lock. */
						struct lock_struct *plock)	/* proposed lock. */
{
	bool lock_types_differ = (ex->lock_type != plock->lock_type);

	/* We can't merge non-conflicting locks on different context - ignore fnum. */

	if (!brl_same_context(&ex->context, &plock->context)) {
		/* Just copy. */
		memcpy(&lck_arr[0], ex, sizeof(struct lock_struct));
		return 1;
	}

	/* We now know we have the same context. */

	/* Did we overlap ? */

/*********************************************
                                        +---------+
                                        | ex      |
                                        +---------+
                         +-------+
                         | plock |
                         +-------+
OR....
        +---------+
        |  ex     |
        +---------+
**********************************************/

	if ( (ex->start > (plock->start + plock->size)) ||
		(plock->start > (ex->start + ex->size))) {

		/* No overlap with this lock - copy existing. */

		memcpy(&lck_arr[0], ex, sizeof(struct lock_struct));
		return 1;
	}

/*********************************************
        +---------------------------+
        |          ex               |
        +---------------------------+
        +---------------------------+
        |       plock               | -> replace with plock.
        +---------------------------+
OR
             +---------------+
             |       ex      |
             +---------------+
        +---------------------------+
        |       plock               | -> replace with plock.
        +---------------------------+

**********************************************/

	if ( (ex->start >= plock->start) &&
		(ex->start + ex->size <= plock->start + plock->size) ) {

		/* Replace - discard existing lock. */

		return 0;
	}

/*********************************************
Adjacent after.
                        +-------+
                        |  ex   |
                        +-------+
        +---------------+
        |   plock       |
        +---------------+

BECOMES....
        +---------------+-------+
        |   plock       | ex    | - different lock types.
        +---------------+-------+
OR.... (merge)
        +-----------------------+
        |   plock               | - same lock type.
        +-----------------------+
**********************************************/

	if (plock->start + plock->size == ex->start) {

		/* If the lock types are the same, we merge, if different, we
		   add the remainder of the old lock. */

		if (lock_types_differ) {
			/* Add existing. */
			memcpy(&lck_arr[0], ex, sizeof(struct lock_struct));
			return 1;
		} else {
			/* Merge - adjust incoming lock as we may have more
			 * merging to come. */
			plock->size += ex->size;
			return 0;
		}
	}

/*********************************************
Adjacent before.
        +-------+
        |  ex   |
        +-------+
                +---------------+
                |   plock       |
                +---------------+
BECOMES....
        +-------+---------------+
        | ex    |   plock       | - different lock types
        +-------+---------------+

OR.... (merge)
        +-----------------------+
        |      plock            | - same lock type.
        +-----------------------+

**********************************************/

	if (ex->start + ex->size == plock->start) {

		/* If the lock types are the same, we merge, if different, we
		   add the existing lock. */

		if (lock_types_differ) {
			memcpy(&lck_arr[0], ex, sizeof(struct lock_struct));
			return 1;
		} else {
			/* Merge - adjust incoming lock as we may have more
			 * merging to come. */
			plock->start = ex->start;
			plock->size += ex->size;
			return 0;
		}
	}

/*********************************************
Overlap after.
        +-----------------------+
        |          ex           |
        +-----------------------+
        +---------------+
        |   plock       |
        +---------------+
OR
               +----------------+
               |       ex       |
               +----------------+
        +---------------+
        |   plock       |
        +---------------+

BECOMES....
        +---------------+-------+
        |   plock       | ex    | - different lock types.
        +---------------+-------+
OR.... (merge)
        +-----------------------+
        |   plock               | - same lock type.
        +-----------------------+
**********************************************/

	if ( (ex->start >= plock->start) &&
		(ex->start <= plock->start + plock->size) &&
		(ex->start + ex->size > plock->start + plock->size) ) {

		/* If the lock types are the same, we merge, if different, we
		   add the remainder of the old lock. */

		if (lock_types_differ) {
			/* Add remaining existing. */
			memcpy(&lck_arr[0], ex, sizeof(struct lock_struct));
			/* Adjust existing start and size. */
			lck_arr[0].start = plock->start + plock->size;
			lck_arr[0].size = (ex->start + ex->size) - (plock->start + plock->size);
			return 1;
		} else {
			/* Merge - adjust incoming lock as we may have more
			 * merging to come. */
			plock->size += (ex->start + ex->size) - (plock->start + plock->size);
			return 0;
		}
	}

/*********************************************
Overlap before.
        +-----------------------+
        |  ex                   |
        +-----------------------+
                +---------------+
                |   plock       |
                +---------------+
OR
        +-------------+
        |  ex         |
        +-------------+
                +---------------+
                |   plock       |
                +---------------+

BECOMES....
        +-------+---------------+
        | ex    |   plock       | - different lock types
        +-------+---------------+

OR.... (merge)
        +-----------------------+
        |      plock            | - same lock type.
        +-----------------------+

**********************************************/

	if ( (ex->start < plock->start) &&
			(ex->start + ex->size >= plock->start) &&
			(ex->start + ex->size <= plock->start + plock->size) ) {

		/* If the lock types are the same, we merge, if different, we
		   add the truncated old lock. */

		if (lock_types_differ) {
			memcpy(&lck_arr[0], ex, sizeof(struct lock_struct));
			/* Adjust existing size. */
			lck_arr[0].size = plock->start - ex->start;
			return 1;
		} else {
			/* Merge - adjust incoming lock as we may have more
			 * merging to come. MUST ADJUST plock SIZE FIRST ! */
			plock->size += (plock->start - ex->start);
			plock->start = ex->start;
			return 0;
		}
	}

/*********************************************
Complete overlap.
        +---------------------------+
        |        ex                 |
        +---------------------------+
                +---------+
                |  plock  |
                +---------+
BECOMES.....
        +-------+---------+---------+
        | ex    |  plock  | ex      | - different lock types.
        +-------+---------+---------+
OR
        +---------------------------+
        |        plock              | - same lock type.
        +---------------------------+
**********************************************/

	if ( (ex->start < plock->start) && (ex->start + ex->size > plock->start + plock->size) ) {

		if (lock_types_differ) {

			/* We have to split ex into two locks here. */

			memcpy(&lck_arr[0], ex, sizeof(struct lock_struct));
			memcpy(&lck_arr[1], ex, sizeof(struct lock_struct));

			/* Adjust first existing size. */
			lck_arr[0].size = plock->start - ex->start;

			/* Adjust second existing start and size. */
			lck_arr[1].start = plock->start + plock->size;
			lck_arr[1].size = (ex->start + ex->size) - (plock->start + plock->size);
			return 2;
		} else {
			/* Just eat the existing locks, merge them into plock. */
			plock->start = ex->start;
			plock->size = ex->size;
			return 0;
		}
	}

	/* Never get here. */
	smb_panic("brlock_posix_split_merge");
	/* Notreached. */

	/* Keep some compilers happy. */
	return 0;
}

/****************************************************************************
 Lock a range of bytes - POSIX lock semantics.
 We must cope with range splits and merges.
****************************************************************************/

static NTSTATUS brl_lock_posix(struct byte_range_lock *br_lck,
			       struct lock_struct *plock)
{
	unsigned int i, count, posix_count;
	struct lock_struct *locks = br_lck->lock_data;
	struct lock_struct *tp;
	bool break_oplocks = false;
	NTSTATUS status;

	/* No zero-zero locks for POSIX. */
	if (plock->start == 0 && plock->size == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Don't allow 64-bit lock wrap. */
	if (plock->start + plock->size - 1 < plock->start) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* The worst case scenario here is we have to split an
	   existing POSIX lock range into two, and add our lock,
	   so we need at most 2 more entries. */

	tp = talloc_array(br_lck, struct lock_struct, br_lck->num_locks + 2);
	if (!tp) {
		return NT_STATUS_NO_MEMORY;
	}

	count = posix_count = 0;

	for (i=0; i < br_lck->num_locks; i++) {
		struct lock_struct *curr_lock = &locks[i];

		if (curr_lock->lock_flav == WINDOWS_LOCK) {
			/* Do any Windows flavour locks conflict ? */
			if (brl_conflict(curr_lock, plock)) {
				if (!serverid_exists(&curr_lock->context.pid)) {
					curr_lock->context.pid.pid = 0;
					br_lck->modified = true;
					continue;
				}
				/* No games with error messages. */
				TALLOC_FREE(tp);
				/* Remember who blocked us. */
				plock->context.smblctx = curr_lock->context.smblctx;
				return NT_STATUS_LOCK_NOT_GRANTED;
			}
			/* Just copy the Windows lock into the new array. */
			memcpy(&tp[count], curr_lock, sizeof(struct lock_struct));
			count++;
		} else {
			unsigned int tmp_count = 0;

			/* POSIX conflict semantics are different. */
			if (brl_conflict_posix(curr_lock, plock)) {
				if (!serverid_exists(&curr_lock->context.pid)) {
					curr_lock->context.pid.pid = 0;
					br_lck->modified = true;
					continue;
				}
				/* Can't block ourselves with POSIX locks. */
				/* No games with error messages. */
				TALLOC_FREE(tp);
				/* Remember who blocked us. */
				plock->context.smblctx = curr_lock->context.smblctx;
				return NT_STATUS_LOCK_NOT_GRANTED;
			}

			/* Work out overlaps. */
			tmp_count += brlock_posix_split_merge(&tp[count], curr_lock, plock);
			posix_count += tmp_count;
			count += tmp_count;
		}
	}

	/*
	 * Break oplocks while we hold a brl. Since lock() and unlock() calls
	 * are not symetric with POSIX semantics, we cannot guarantee our
	 * contend_level2_oplocks_begin/end calls will be acquired and
	 * released one-for-one as with Windows semantics. Therefore we only
	 * call contend_level2_oplocks_begin if this is the first POSIX brl on
	 * the file.
	 */
	break_oplocks = (posix_count == 0);
	if (break_oplocks) {
		contend_level2_oplocks_begin(br_lck->fsp,
					     LEVEL2_CONTEND_POSIX_BRL);
	}

	/* Try and add the lock in order, sorted by lock start. */
	for (i=0; i < count; i++) {
		struct lock_struct *curr_lock = &tp[i];

		if (curr_lock->start <= plock->start) {
			continue;
		}
	}

	if (i < count) {
		memmove(&tp[i+1], &tp[i],
			(count - i)*sizeof(struct lock_struct));
	}
	memcpy(&tp[i], plock, sizeof(struct lock_struct));
	count++;

	/* We can get the POSIX lock, now see if it needs to
	   be mapped into a lower level POSIX one, and if so can
	   we get it ? */

	if (lp_posix_locking(br_lck->fsp->conn->params)) {
		int errno_ret;

		/* The lower layer just needs to attempt to
		   get the system POSIX lock. We've weeded out
		   any conflicts above. */

		if (!set_posix_lock_posix_flavour(br_lck->fsp,
				plock->start,
				plock->size,
				plock->lock_type,
				&plock->context,
				&errno_ret)) {

			/* We don't know who blocked us. */
			plock->context.smblctx = 0xFFFFFFFFFFFFFFFFLL;

			if (errno_ret == EACCES || errno_ret == EAGAIN) {
				TALLOC_FREE(tp);
				status = NT_STATUS_LOCK_NOT_GRANTED;
				goto fail;
			} else {
				TALLOC_FREE(tp);
				status = map_nt_error_from_unix(errno);
				goto fail;
			}
		}
	}

	/* If we didn't use all the allocated size,
	 * Realloc so we don't leak entries per lock call. */
	if (count < br_lck->num_locks + 2) {
		tp = talloc_realloc(br_lck, tp, struct lock_struct, count);
		if (!tp) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}

	br_lck->num_locks = count;
	TALLOC_FREE(br_lck->lock_data);
	br_lck->lock_data = tp;
	locks = tp;
	br_lck->modified = True;

	/* A successful downgrade from write to read lock can trigger a lock
	   re-evalutation where waiting readers can now proceed. */

	return NT_STATUS_OK;
 fail:
	if (break_oplocks) {
		contend_level2_oplocks_end(br_lck->fsp,
					   LEVEL2_CONTEND_POSIX_BRL);
	}
	return status;
}

NTSTATUS smb_vfs_call_brl_lock_windows(struct vfs_handle_struct *handle,
				       struct byte_range_lock *br_lck,
				       struct lock_struct *plock)
{
	VFS_FIND(brl_lock_windows);
	return handle->fns->brl_lock_windows_fn(handle, br_lck, plock);
}

/****************************************************************************
 Lock a range of bytes.
****************************************************************************/

NTSTATUS brl_lock(
	struct byte_range_lock *br_lck,
	uint64_t smblctx,
	struct server_id pid,
	br_off start,
	br_off size,
	enum brl_type lock_type,
	enum brl_flavour lock_flav,
	struct server_id *blocker_pid,
	uint64_t *psmblctx)
{
	NTSTATUS ret;
	struct lock_struct lock;

	ZERO_STRUCT(lock);

#if !ZERO_ZERO
	if (start == 0 && size == 0) {
		DEBUG(0,("client sent 0/0 lock - please report this\n"));
	}
#endif

	lock = (struct lock_struct) {
		.context.smblctx = smblctx,
		.context.pid = pid,
		.context.tid = br_lck->fsp->conn->cnum,
		.start = start,
		.size = size,
		.fnum = br_lck->fsp->fnum,
		.lock_type = lock_type,
		.lock_flav = lock_flav
	};

	if (lock_flav == WINDOWS_LOCK) {
		ret = SMB_VFS_BRL_LOCK_WINDOWS(
			br_lck->fsp->conn, br_lck, &lock);
	} else {
		ret = brl_lock_posix(br_lck, &lock);
	}

#if ZERO_ZERO
	/* sort the lock list */
	TYPESAFE_QSORT(br_lck->lock_data, (size_t)br_lck->num_locks, lock_compare);
#endif
	/* If we're returning an error, return who blocked us. */
	if (!NT_STATUS_IS_OK(ret) && psmblctx) {
		*blocker_pid = lock.context.pid;
		*psmblctx = lock.context.smblctx;
	}
	return ret;
}

/****************************************************************************
 Unlock a range of bytes - Windows semantics.
****************************************************************************/

bool brl_unlock_windows_default(struct byte_range_lock *br_lck,
				const struct lock_struct *plock)
{
	unsigned int i;
	struct lock_struct *locks = br_lck->lock_data;
	enum brl_type deleted_lock_type = READ_LOCK; /* shut the compiler up.... */

	SMB_ASSERT(plock->lock_type == UNLOCK_LOCK);

#if ZERO_ZERO
	/* Delete write locks by preference... The lock list
	   is sorted in the zero zero case. */

	for (i = 0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->lock_type == WRITE_LOCK &&
		    brl_same_context(&lock->context, &plock->context) &&
		    lock->fnum == plock->fnum &&
		    lock->lock_flav == WINDOWS_LOCK &&
		    lock->start == plock->start &&
		    lock->size == plock->size) {

			/* found it - delete it */
			deleted_lock_type = lock->lock_type;
			break;
		}
	}

	if (i != br_lck->num_locks) {
		/* We found it - don't search again. */
		goto unlock_continue;
	}
#endif

	for (i = 0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &locks[i];

		/* Only remove our own locks that match in start, size, and flavour. */
		if (brl_same_context(&lock->context, &plock->context) &&
					lock->fnum == plock->fnum &&
					lock->lock_flav == WINDOWS_LOCK &&
					lock->start == plock->start &&
					lock->size == plock->size ) {
			deleted_lock_type = lock->lock_type;
			break;
		}
	}

	if (i == br_lck->num_locks) {
		/* we didn't find it */
		return False;
	}

#if ZERO_ZERO
  unlock_continue:
#endif

	ARRAY_DEL_ELEMENT(locks, i, br_lck->num_locks);
	br_lck->num_locks -= 1;
	br_lck->modified = True;

	/* Unlock the underlying POSIX regions. */
	if(lp_posix_locking(br_lck->fsp->conn->params)) {
		release_posix_lock_windows_flavour(br_lck->fsp,
				plock->start,
				plock->size,
				deleted_lock_type,
				&plock->context,
				locks,
				br_lck->num_locks);
	}

	contend_level2_oplocks_end(br_lck->fsp, LEVEL2_CONTEND_WINDOWS_BRL);
	return True;
}

/****************************************************************************
 Unlock a range of bytes - POSIX semantics.
****************************************************************************/

static bool brl_unlock_posix(struct byte_range_lock *br_lck,
			     struct lock_struct *plock)
{
	unsigned int i, count;
	struct lock_struct *tp;
	struct lock_struct *locks = br_lck->lock_data;
	bool overlap_found = False;

	/* No zero-zero locks for POSIX. */
	if (plock->start == 0 && plock->size == 0) {
		return False;
	}

	/* Don't allow 64-bit lock wrap. */
	if (plock->start + plock->size < plock->start ||
			plock->start + plock->size < plock->size) {
		DEBUG(10,("brl_unlock_posix: lock wrap\n"));
		return False;
	}

	/* The worst case scenario here is we have to split an
	   existing POSIX lock range into two, so we need at most
	   1 more entry. */

	tp = talloc_array(br_lck, struct lock_struct, br_lck->num_locks + 1);
	if (!tp) {
		DEBUG(10,("brl_unlock_posix: malloc fail\n"));
		return False;
	}

	count = 0;
	for (i = 0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &locks[i];
		unsigned int tmp_count;

		/* Only remove our own locks - ignore fnum. */
		if (!brl_same_context(&lock->context, &plock->context)) {
			memcpy(&tp[count], lock, sizeof(struct lock_struct));
			count++;
			continue;
		}

		if (lock->lock_flav == WINDOWS_LOCK) {
			/* Do any Windows flavour locks conflict ? */
			if (brl_conflict(lock, plock)) {
				TALLOC_FREE(tp);
				return false;
			}
			/* Just copy the Windows lock into the new array. */
			memcpy(&tp[count], lock, sizeof(struct lock_struct));
			count++;
			continue;
		}

		/* Work out overlaps. */
		tmp_count = brlock_posix_split_merge(&tp[count], lock, plock);

		if (tmp_count == 0) {
			/* plock overlapped the existing lock completely,
			   or replaced it. Don't copy the existing lock. */
			overlap_found = true;
		} else if (tmp_count == 1) {
			/* Either no overlap, (simple copy of existing lock) or
			 * an overlap of an existing lock. */
			/* If the lock changed size, we had an overlap. */
			if (tp[count].size != lock->size) {
				overlap_found = true;
			}
			count += tmp_count;
		} else if (tmp_count == 2) {
			/* We split a lock range in two. */
			overlap_found = true;
			count += tmp_count;

			/* Optimisation... */
			/* We know we're finished here as we can't overlap any
			   more POSIX locks. Copy the rest of the lock array. */

			if (i < br_lck->num_locks - 1) {
				memcpy(&tp[count], &locks[i+1],
					sizeof(*locks)*((br_lck->num_locks-1) - i));
				count += ((br_lck->num_locks-1) - i);
			}
			break;
		}

	}

	if (!overlap_found) {
		/* Just ignore - no change. */
		TALLOC_FREE(tp);
		DEBUG(10,("brl_unlock_posix: No overlap - unlocked.\n"));
		return True;
	}

	/* Unlock any POSIX regions. */
	if(lp_posix_locking(br_lck->fsp->conn->params)) {
		release_posix_lock_posix_flavour(br_lck->fsp,
						plock->start,
						plock->size,
						&plock->context,
						tp,
						count);
	}

	/* Realloc so we don't leak entries per unlock call. */
	if (count) {
		tp = talloc_realloc(br_lck, tp, struct lock_struct, count);
		if (!tp) {
			DEBUG(10,("brl_unlock_posix: realloc fail\n"));
			return False;
		}
	} else {
		/* We deleted the last lock. */
		TALLOC_FREE(tp);
		tp = NULL;
	}

	contend_level2_oplocks_end(br_lck->fsp,
				   LEVEL2_CONTEND_POSIX_BRL);

	br_lck->num_locks = count;
	TALLOC_FREE(br_lck->lock_data);
	locks = tp;
	br_lck->lock_data = tp;
	br_lck->modified = True;

	return True;
}

bool smb_vfs_call_brl_unlock_windows(struct vfs_handle_struct *handle,
				     struct byte_range_lock *br_lck,
				     const struct lock_struct *plock)
{
	VFS_FIND(brl_unlock_windows);
	return handle->fns->brl_unlock_windows_fn(handle, br_lck, plock);
}

/****************************************************************************
 Unlock a range of bytes.
****************************************************************************/

bool brl_unlock(struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav)
{
	struct lock_struct lock;

	lock.context.smblctx = smblctx;
	lock.context.pid = pid;
	lock.context.tid = br_lck->fsp->conn->cnum;
	lock.start = start;
	lock.size = size;
	lock.fnum = br_lck->fsp->fnum;
	lock.lock_type = UNLOCK_LOCK;
	lock.lock_flav = lock_flav;

	if (lock_flav == WINDOWS_LOCK) {
		return SMB_VFS_BRL_UNLOCK_WINDOWS(
			br_lck->fsp->conn, br_lck, &lock);
	} else {
		return brl_unlock_posix(br_lck, &lock);
	}
}

/****************************************************************************
 Test if we could add a lock if we wanted to.
 Returns True if the region required is currently unlocked, False if locked.
****************************************************************************/

bool brl_locktest(struct byte_range_lock *br_lck,
		  const struct lock_struct *rw_probe)
{
	bool ret = True;
	unsigned int i;
	struct lock_struct *locks = br_lck->lock_data;
	files_struct *fsp = br_lck->fsp;

	/* Make sure existing locks don't conflict */
	for (i=0; i < br_lck->num_locks; i++) {
		/*
		 * Our own locks don't conflict.
		 */
		if (brl_conflict_other(&locks[i], rw_probe)) {
			if (br_lck->record == NULL) {
				/* readonly */
				return false;
			}

			if (!serverid_exists(&locks[i].context.pid)) {
				locks[i].context.pid.pid = 0;
				br_lck->modified = true;
				continue;
			}

			return False;
		}
	}

	/*
	 * There is no lock held by an SMB daemon, check to
	 * see if there is a POSIX lock from a UNIX or NFS process.
	 * This only conflicts with Windows locks, not POSIX locks.
	 */

	if(lp_posix_locking(fsp->conn->params) &&
	   (rw_probe->lock_flav == WINDOWS_LOCK)) {
		/*
		 * Make copies -- is_posix_locked might modify the values
		 */

		br_off start = rw_probe->start;
		br_off size = rw_probe->size;
		enum brl_type lock_type = rw_probe->lock_type;

		ret = is_posix_locked(fsp, &start, &size, &lock_type, WINDOWS_LOCK);

		DEBUG(10, ("brl_locktest: posix start=%ju len=%ju %s for %s "
			   "file %s\n", (uintmax_t)start, (uintmax_t)size,
			   ret ? "locked" : "unlocked",
			   fsp_fnum_dbg(fsp), fsp_str_dbg(fsp)));

		/* We need to return the inverse of is_posix_locked. */
		ret = !ret;
        }

	/* no conflicts - we could have added it */
	return ret;
}

/****************************************************************************
 Query for existing locks.
****************************************************************************/

NTSTATUS brl_lockquery(struct byte_range_lock *br_lck,
		uint64_t *psmblctx,
		struct server_id pid,
		br_off *pstart,
		br_off *psize,
		enum brl_type *plock_type,
		enum brl_flavour lock_flav)
{
	unsigned int i;
	struct lock_struct lock;
	const struct lock_struct *locks = br_lck->lock_data;
	files_struct *fsp = br_lck->fsp;

	lock.context.smblctx = *psmblctx;
	lock.context.pid = pid;
	lock.context.tid = br_lck->fsp->conn->cnum;
	lock.start = *pstart;
	lock.size = *psize;
	lock.fnum = fsp->fnum;
	lock.lock_type = *plock_type;
	lock.lock_flav = lock_flav;

	/* Make sure existing locks don't conflict */
	for (i=0; i < br_lck->num_locks; i++) {
		const struct lock_struct *exlock = &locks[i];
		bool conflict = False;

		if (exlock->lock_flav == WINDOWS_LOCK) {
			conflict = brl_conflict(exlock, &lock);
		} else {
			conflict = brl_conflict_posix(exlock, &lock);
		}

		if (conflict) {
			*psmblctx = exlock->context.smblctx;
        		*pstart = exlock->start;
		        *psize = exlock->size;
        		*plock_type = exlock->lock_type;
			return NT_STATUS_LOCK_NOT_GRANTED;
		}
	}

	/*
	 * There is no lock held by an SMB daemon, check to
	 * see if there is a POSIX lock from a UNIX or NFS process.
	 */

	if(lp_posix_locking(fsp->conn->params)) {
		bool ret = is_posix_locked(fsp, pstart, psize, plock_type, POSIX_LOCK);

		DEBUG(10, ("brl_lockquery: posix start=%ju len=%ju %s for %s "
			   "file %s\n", (uintmax_t)*pstart,
			   (uintmax_t)*psize, ret ? "locked" : "unlocked",
			   fsp_fnum_dbg(fsp), fsp_str_dbg(fsp)));

		if (ret) {
			/* Hmmm. No clue what to set smblctx to - use -1. */
			*psmblctx = 0xFFFFFFFFFFFFFFFFLL;
			return NT_STATUS_LOCK_NOT_GRANTED;
		}
        }

	return NT_STATUS_OK;
}


/****************************************************************************
 Remove any locks associated with a open file.
 We return True if this process owns any other Windows locks on this
 fd and so we should not immediately close the fd.
****************************************************************************/

void brl_close_fnum(struct byte_range_lock *br_lck)
{
	files_struct *fsp = br_lck->fsp;
	uint32_t tid = fsp->conn->cnum;
	uint64_t fnum = fsp->fnum;
	unsigned int i;
	struct lock_struct *locks = br_lck->lock_data;
	struct server_id pid = messaging_server_id(fsp->conn->sconn->msg_ctx);
	struct lock_struct *locks_copy;
	unsigned int num_locks_copy;

	/* Copy the current lock array. */
	if (br_lck->num_locks) {
		locks_copy = (struct lock_struct *)talloc_memdup(br_lck, locks, br_lck->num_locks * sizeof(struct lock_struct));
		if (!locks_copy) {
			smb_panic("brl_close_fnum: talloc failed");
			}
	} else {
		locks_copy = NULL;
	}

	num_locks_copy = br_lck->num_locks;

	for (i=0; i < num_locks_copy; i++) {
		struct lock_struct *lock = &locks_copy[i];

		if (lock->context.tid == tid &&
		    server_id_equal(&lock->context.pid, &pid) &&
				(lock->fnum == fnum)) {
			brl_unlock(
				br_lck,
				lock->context.smblctx,
				pid,
				lock->start,
				lock->size,
				lock->lock_flav);
		}
	}
}

bool brl_mark_disconnected(struct files_struct *fsp)
{
	uint32_t tid = fsp->conn->cnum;
	uint64_t smblctx;
	uint64_t fnum = fsp->fnum;
	unsigned int i;
	struct server_id self = messaging_server_id(fsp->conn->sconn->msg_ctx);
	struct byte_range_lock *br_lck = NULL;

	if (fsp->op == NULL) {
		return false;
	}

	smblctx = fsp->op->global->open_persistent_id;

	if (!fsp->op->global->durable) {
		return false;
	}

	if (fsp->current_lock_count == 0) {
		return true;
	}

	br_lck = brl_get_locks(talloc_tos(), fsp);
	if (br_lck == NULL) {
		return false;
	}

	for (i=0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &br_lck->lock_data[i];

		/*
		 * as this is a durable handle, we only expect locks
		 * of the current file handle!
		 */

		if (lock->context.smblctx != smblctx) {
			TALLOC_FREE(br_lck);
			return false;
		}

		if (lock->context.tid != tid) {
			TALLOC_FREE(br_lck);
			return false;
		}

		if (!server_id_equal(&lock->context.pid, &self)) {
			TALLOC_FREE(br_lck);
			return false;
		}

		if (lock->fnum != fnum) {
			TALLOC_FREE(br_lck);
			return false;
		}

		server_id_set_disconnected(&lock->context.pid);
		lock->context.tid = TID_FIELD_INVALID;
		lock->fnum = FNUM_FIELD_INVALID;
	}

	br_lck->modified = true;
	TALLOC_FREE(br_lck);
	return true;
}

bool brl_reconnect_disconnected(struct files_struct *fsp)
{
	uint32_t tid = fsp->conn->cnum;
	uint64_t smblctx;
	uint64_t fnum = fsp->fnum;
	unsigned int i;
	struct server_id self = messaging_server_id(fsp->conn->sconn->msg_ctx);
	struct byte_range_lock *br_lck = NULL;

	if (fsp->op == NULL) {
		return false;
	}

	smblctx = fsp->op->global->open_persistent_id;

	if (!fsp->op->global->durable) {
		return false;
	}

	/*
	 * When reconnecting, we do not want to validate the brlock entries
	 * and thereby remove our own (disconnected) entries but reactivate
	 * them instead.
	 */

	br_lck = brl_get_locks(talloc_tos(), fsp);
	if (br_lck == NULL) {
		return false;
	}

	if (br_lck->num_locks == 0) {
		TALLOC_FREE(br_lck);
		return true;
	}

	for (i=0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &br_lck->lock_data[i];

		/*
		 * as this is a durable handle we only expect locks
		 * of the current file handle!
		 */

		if (lock->context.smblctx != smblctx) {
			TALLOC_FREE(br_lck);
			return false;
		}

		if (lock->context.tid != TID_FIELD_INVALID) {
			TALLOC_FREE(br_lck);
			return false;
		}

		if (!server_id_is_disconnected(&lock->context.pid)) {
			TALLOC_FREE(br_lck);
			return false;
		}

		if (lock->fnum != FNUM_FIELD_INVALID) {
			TALLOC_FREE(br_lck);
			return false;
		}

		lock->context.pid = self;
		lock->context.tid = tid;
		lock->fnum = fnum;
	}

	fsp->current_lock_count = br_lck->num_locks;
	br_lck->modified = true;
	TALLOC_FREE(br_lck);
	return true;
}

struct brl_forall_cb {
	void (*fn)(struct file_id id, struct server_id pid,
		   enum brl_type lock_type,
		   enum brl_flavour lock_flav,
		   br_off start, br_off size,
		   void *private_data);
	void *private_data;
};

/****************************************************************************
 Traverse the whole database with this function, calling traverse_callback
 on each lock.
****************************************************************************/

static int brl_traverse_fn(struct db_record *rec, void *state)
{
	struct brl_forall_cb *cb = (struct brl_forall_cb *)state;
	struct lock_struct *locks;
	struct file_id *key;
	unsigned int i;
	unsigned int num_locks = 0;
	TDB_DATA dbkey;
	TDB_DATA value;

	dbkey = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	/* In a traverse function we must make a copy of
	   dbuf before modifying it. */

	locks = (struct lock_struct *)talloc_memdup(
		talloc_tos(), value.dptr, value.dsize);
	if (!locks) {
		return -1; /* Terminate traversal. */
	}

	key = (struct file_id *)dbkey.dptr;
	num_locks = value.dsize/sizeof(*locks);

	if (cb->fn) {
		for ( i=0; i<num_locks; i++) {
			cb->fn(*key,
				locks[i].context.pid,
				locks[i].lock_type,
				locks[i].lock_flav,
				locks[i].start,
				locks[i].size,
				cb->private_data);
		}
	}

	TALLOC_FREE(locks);
	return 0;
}

/*******************************************************************
 Call the specified function on each lock in the database.
********************************************************************/

int brl_forall(void (*fn)(struct file_id id, struct server_id pid,
			  enum brl_type lock_type,
			  enum brl_flavour lock_flav,
			  br_off start, br_off size,
			  void *private_data),
	       void *private_data)
{
	struct brl_forall_cb cb;
	NTSTATUS status;
	int count = 0;

	if (!brlock_db) {
		return 0;
	}
	cb.fn = fn;
	cb.private_data = private_data;
	status = dbwrap_traverse(brlock_db, brl_traverse_fn, &cb, &count);

	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	} else {
		return count;
	}
}

/*******************************************************************
 Store a potentially modified set of byte range lock data back into
 the database.
 Unlock the record.
********************************************************************/

static void byte_range_lock_flush(struct byte_range_lock *br_lck)
{
	unsigned i;
	struct lock_struct *locks = br_lck->lock_data;

	if (!br_lck->modified) {
		DEBUG(10, ("br_lck not modified\n"));
		goto done;
	}

	i = 0;

	while (i < br_lck->num_locks) {
		if (locks[i].context.pid.pid == 0) {
			/*
			 * Autocleanup, the process conflicted and does not
			 * exist anymore.
			 */
			locks[i] = locks[br_lck->num_locks-1];
			br_lck->num_locks -= 1;
		} else {
			i += 1;
		}
	}

	if (br_lck->num_locks == 0) {
		/* No locks - delete this entry. */
		NTSTATUS status = dbwrap_record_delete(br_lck->record);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("delete_rec returned %s\n",
				  nt_errstr(status)));
			smb_panic("Could not delete byte range lock entry");
		}
	} else {
		TDB_DATA data = {
			.dsize = br_lck->num_locks * sizeof(struct lock_struct),
			.dptr = (uint8_t *)br_lck->lock_data,
		};
		NTSTATUS status;

		status = dbwrap_record_store(br_lck->record, data, TDB_REPLACE);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("store returned %s\n", nt_errstr(status)));
			smb_panic("Could not store byte range mode entry");
		}
	}

	DEBUG(10, ("seqnum=%d\n", dbwrap_get_seqnum(brlock_db)));

 done:
	br_lck->modified = false;
	TALLOC_FREE(br_lck->record);
}

static int byte_range_lock_destructor(struct byte_range_lock *br_lck)
{
	byte_range_lock_flush(br_lck);
	return 0;
}

static bool brl_parse_data(struct byte_range_lock *br_lck, TDB_DATA data)
{
	size_t data_len;

	if (data.dsize == 0) {
		return true;
	}
	if (data.dsize % sizeof(struct lock_struct) != 0) {
		DEBUG(1, ("Invalid data size: %u\n", (unsigned)data.dsize));
		return false;
	}

	br_lck->num_locks = data.dsize / sizeof(struct lock_struct);
	data_len = br_lck->num_locks * sizeof(struct lock_struct);

	br_lck->lock_data = talloc_memdup(br_lck, data.dptr, data_len);
	if (br_lck->lock_data == NULL) {
		DEBUG(1, ("talloc_memdup failed\n"));
		return false;
	}
	return true;
}

/*******************************************************************
 Fetch a set of byte range lock data from the database.
 Leave the record locked.
 TALLOC_FREE(brl) will release the lock in the destructor.
********************************************************************/

struct byte_range_lock *brl_get_locks(TALLOC_CTX *mem_ctx, files_struct *fsp)
{
	TDB_DATA key, data;
	struct byte_range_lock *br_lck;

	br_lck = talloc_zero(mem_ctx, struct byte_range_lock);
	if (br_lck == NULL) {
		return NULL;
	}

	br_lck->fsp = fsp;

	key.dptr = (uint8_t *)&fsp->file_id;
	key.dsize = sizeof(struct file_id);

	br_lck->record = dbwrap_fetch_locked(brlock_db, br_lck, key);

	if (br_lck->record == NULL) {
		DEBUG(3, ("Could not lock byte range lock entry\n"));
		TALLOC_FREE(br_lck);
		return NULL;
	}

	data = dbwrap_record_get_value(br_lck->record);

	if (!brl_parse_data(br_lck, data)) {
		TALLOC_FREE(br_lck);
		return NULL;
	}

	talloc_set_destructor(br_lck, byte_range_lock_destructor);

	if (DEBUGLEVEL >= 10) {
		unsigned int i;
		struct file_id_buf buf;
		struct lock_struct *locks = br_lck->lock_data;
		DBG_DEBUG("%u current locks on file_id %s\n",
			  br_lck->num_locks,
			  file_id_str_buf(fsp->file_id, &buf));
		for( i = 0; i < br_lck->num_locks; i++) {
			print_lock_struct(i, &locks[i]);
		}
	}

	return br_lck;
}

struct byte_range_lock *brl_get_locks_for_locking(TALLOC_CTX *mem_ctx,
						  files_struct *fsp,
						  TALLOC_CTX *req_mem_ctx,
						  const struct GUID *req_guid)
{
	struct byte_range_lock *br_lck = NULL;

	br_lck = brl_get_locks(mem_ctx, fsp);
	if (br_lck == NULL) {
		return NULL;
	}
	SMB_ASSERT(req_mem_ctx != NULL);
	br_lck->req_mem_ctx = req_mem_ctx;
	SMB_ASSERT(req_guid != NULL);
	br_lck->req_guid = req_guid;

	return br_lck;
}

struct brl_get_locks_readonly_state {
	TALLOC_CTX *mem_ctx;
	struct byte_range_lock **br_lock;
};

static void brl_get_locks_readonly_parser(TDB_DATA key, TDB_DATA data,
					  void *private_data)
{
	struct brl_get_locks_readonly_state *state =
		(struct brl_get_locks_readonly_state *)private_data;
	struct byte_range_lock *br_lck;

	br_lck = talloc_pooled_object(
		state->mem_ctx, struct byte_range_lock, 1, data.dsize);
	if (br_lck == NULL) {
		*state->br_lock = NULL;
		return;
	}
	*br_lck = (struct byte_range_lock) { 0 };
	if (!brl_parse_data(br_lck, data)) {
		*state->br_lock = NULL;
		return;
	}
	*state->br_lock = br_lck;
}

struct byte_range_lock *brl_get_locks_readonly(files_struct *fsp)
{
	struct byte_range_lock *br_lock = NULL;
	struct brl_get_locks_readonly_state state;
	NTSTATUS status;

	DEBUG(10, ("seqnum=%d, fsp->brlock_seqnum=%d\n",
		   dbwrap_get_seqnum(brlock_db), fsp->brlock_seqnum));

	if ((fsp->brlock_rec != NULL)
	    && (dbwrap_get_seqnum(brlock_db) == fsp->brlock_seqnum)) {
		/*
		 * We have cached the brlock_rec and the database did not
		 * change.
		 */
		return fsp->brlock_rec;
	}

	/*
	 * Parse the record fresh from the database
	 */

	state.mem_ctx = fsp;
	state.br_lock = &br_lock;

	status = dbwrap_parse_record(
		brlock_db,
		make_tdb_data((uint8_t *)&fsp->file_id,
			      sizeof(fsp->file_id)),
		brl_get_locks_readonly_parser, &state);

	if (NT_STATUS_EQUAL(status,NT_STATUS_NOT_FOUND)) {
		/*
		 * No locks on this file. Return an empty br_lock.
		 */
		br_lock = talloc_zero(fsp, struct byte_range_lock);
		if (br_lock == NULL) {
			return NULL;
		}

	} else if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Could not parse byte range lock record: "
			  "%s\n", nt_errstr(status)));
		return NULL;
	}
	if (br_lock == NULL) {
		return NULL;
	}

	br_lock->fsp = fsp;
	br_lock->modified = false;
	br_lock->record = NULL;

	/*
	 * Cache the brlock struct, invalidated when the dbwrap_seqnum
	 * changes. See beginning of this routine.
	 */
	TALLOC_FREE(fsp->brlock_rec);
	fsp->brlock_rec = br_lock;
	fsp->brlock_seqnum = dbwrap_get_seqnum(brlock_db);

	return br_lock;
}

bool brl_cleanup_disconnected(struct file_id fid, uint64_t open_persistent_id)
{
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA key, val;
	struct db_record *rec;
	struct lock_struct *lock;
	unsigned n, num;
	struct file_id_buf buf;
	NTSTATUS status;

	key = make_tdb_data((void*)&fid, sizeof(fid));

	rec = dbwrap_fetch_locked(brlock_db, frame, key);
	if (rec == NULL) {
		DBG_INFO("failed to fetch record for file %s\n",
			 file_id_str_buf(fid, &buf));
		goto done;
	}

	val = dbwrap_record_get_value(rec);
	lock = (struct lock_struct*)val.dptr;
	num = val.dsize / sizeof(struct lock_struct);
	if (lock == NULL) {
		DBG_DEBUG("no byte range locks for file %s\n",
			  file_id_str_buf(fid, &buf));
		ret = true;
		goto done;
	}

	for (n=0; n<num; n++) {
		struct lock_context *ctx = &lock[n].context;

		if (!server_id_is_disconnected(&ctx->pid)) {
			struct server_id_buf tmp;
			DBG_INFO("byte range lock "
				 "%s used by server %s, do not cleanup\n",
				 file_id_str_buf(fid, &buf),
				 server_id_str_buf(ctx->pid, &tmp));
			goto done;
		}

		if (ctx->smblctx != open_persistent_id)	{
			DBG_INFO("byte range lock %s expected smblctx %"PRIu64" "
				 "but found %"PRIu64", do not cleanup\n",
				 file_id_str_buf(fid, &buf),
				 open_persistent_id,
				 ctx->smblctx);
			goto done;
		}
	}

	status = dbwrap_record_delete(rec);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("failed to delete record "
			 "for file %s from %s, open %"PRIu64": %s\n",
			 file_id_str_buf(fid, &buf),
			 dbwrap_name(brlock_db),
			 open_persistent_id,
			 nt_errstr(status));
		goto done;
	}

	DBG_DEBUG("file %s cleaned up %u entries from open %"PRIu64"\n",
		  file_id_str_buf(fid, &buf),
		  num,
		  open_persistent_id);

	ret = true;
done:
	talloc_free(frame);
	return ret;
}
