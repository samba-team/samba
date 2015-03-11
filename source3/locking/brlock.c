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
	unsigned int num_locks;
	bool modified;
	uint32_t num_read_oplocks;
	struct lock_struct *lock_data;
	struct db_record *record;
};

/****************************************************************************
 Debug info at level 10 for lock struct.
****************************************************************************/

static void print_lock_struct(unsigned int i, const struct lock_struct *pls)
{
	DEBUG(10,("[%u]: smblctx = %llu, tid = %u, pid = %s, ",
			i,
			(unsigned long long)pls->context.smblctx,
			(unsigned int)pls->context.tid,
			server_id_str(talloc_tos(), &pls->context.pid) ));

	DEBUG(10, ("start = %ju, size = %ju, fnum = %ju, %s %s\n",
		   (uintmax_t)pls->start,
		   (uintmax_t)pls->size,
		   (uintmax_t)pls->fnum,
		   lock_type_name(pls->lock_type),
		   lock_flav_name(pls->lock_flav)));
}

unsigned int brl_num_locks(const struct byte_range_lock *brl)
{
	return brl->num_locks;
}

struct files_struct *brl_fsp(struct byte_range_lock *brl)
{
	return brl->fsp;
}

uint32_t brl_num_read_oplocks(const struct byte_range_lock *brl)
{
	return brl->num_read_oplocks;
}

void brl_set_num_read_oplocks(struct byte_range_lock *brl,
			      uint32_t num_read_oplocks)
{
	DEBUG(10, ("Setting num_read_oplocks to %"PRIu32"\n",
		   num_read_oplocks));
	SMB_ASSERT(brl->record != NULL); /* otherwise we're readonly */
	brl->num_read_oplocks = num_read_oplocks;
	brl->modified = true;
}

/****************************************************************************
 See if two locking contexts are equal.
****************************************************************************/

static bool brl_same_context(const struct lock_context *ctx1,
			     const struct lock_context *ctx2)
{
	return (serverid_equal(&ctx1->pid, &ctx2->pid) &&
		(ctx1->smblctx == ctx2->smblctx) &&
		(ctx1->tid == ctx2->tid));
}

/****************************************************************************
 See if lck1 and lck2 overlap.
****************************************************************************/

static bool brl_overlap(const struct lock_struct *lck1,
                        const struct lock_struct *lck2)
{
	/* XXX Remove for Win7 compatibility. */
	/* this extra check is not redundant - it copes with locks
	   that go beyond the end of 64 bit file space */
	if (lck1->size != 0 &&
	    lck1->start == lck2->start &&
	    lck1->size == lck2->size) {
		return True;
	}

	if (lck1->start >= (lck2->start+lck2->size) ||
	    lck2->start >= (lck1->start+lck1->size)) {
		return False;
	}
	return True;
}

/****************************************************************************
 See if lock2 can be added when lock1 is in place.
****************************************************************************/

static bool brl_conflict(const struct lock_struct *lck1,
			 const struct lock_struct *lck2)
{
	/* Ignore PENDING locks. */
	if (IS_PENDING_LOCK(lck1->lock_type) || IS_PENDING_LOCK(lck2->lock_type))
		return False;

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

	/* Ignore PENDING locks. */
	if (IS_PENDING_LOCK(lck1->lock_type) || IS_PENDING_LOCK(lck2->lock_type))
		return False;

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
	if (IS_PENDING_LOCK(lck1->lock_type) || IS_PENDING_LOCK(lck2->lock_type))
		return False;

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
	if (IS_PENDING_LOCK(lock->lock_type) ||
	    IS_PENDING_LOCK(rw_probe->lock_type)) {
		return False;
	}

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
 Check if an unlock overlaps a pending lock.
****************************************************************************/

static bool brl_pending_overlap(const struct lock_struct *lock, const struct lock_struct *pend_lock)
{
	if ((lock->start <= pend_lock->start) && (lock->start + lock->size > pend_lock->start))
		return True;
	if ((lock->start >= pend_lock->start) && (lock->start < pend_lock->start + pend_lock->size))
		return True;
	return False;
}

/****************************************************************************
 Amazingly enough, w2k3 "remembers" whether the last lock failure on a fnum
 is the same as this one and changes its error code. I wonder if any
 app depends on this ?
****************************************************************************/

static NTSTATUS brl_lock_failed(files_struct *fsp,
				const struct lock_struct *lock,
				bool blocking_lock)
{
	if (lock->start >= 0xEF000000 && (lock->start >> 63) == 0) {
		/* amazing the little things you learn with a test
		   suite. Locks beyond this offset (as a 64 bit
		   number!) always generate the conflict error code,
		   unless the top bit is set */
		if (!blocking_lock) {
			fsp->last_lock_failure = *lock;
		}
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	if (serverid_equal(&lock->context.pid, &fsp->last_lock_failure.context.pid) &&
			lock->context.tid == fsp->last_lock_failure.context.tid &&
			lock->fnum == fsp->last_lock_failure.fnum &&
			lock->start == fsp->last_lock_failure.start) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	if (!blocking_lock) {
		fsp->last_lock_failure = *lock;
	}
	return NT_STATUS_LOCK_NOT_GRANTED;
}

/****************************************************************************
 Open up the brlock.tdb database.
****************************************************************************/

void brl_init(bool read_only)
{
	int tdb_flags;

	if (brlock_db) {
		return;
	}

	tdb_flags = TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH;

	if (!lp_clustering()) {
		/*
		 * We can't use the SEQNUM trick to cache brlock
		 * entries in the clustering case because ctdb seqnum
		 * propagation has a delay.
		 */
		tdb_flags |= TDB_SEQNUM;
	}

	brlock_db = db_open(NULL, lock_path("brlock.tdb"),
			    SMB_OPEN_DATABASE_TDB_HASH_SIZE, tdb_flags,
			    read_only?O_RDONLY:(O_RDWR|O_CREAT), 0644,
			    DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE);
	if (!brlock_db) {
		DEBUG(0,("Failed to open byte range locking database %s\n",
			lock_path("brlock.tdb")));
		return;
	}
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
    struct lock_struct *plock, bool blocking_lock)
{
	unsigned int i;
	files_struct *fsp = br_lck->fsp;
	struct lock_struct *locks = br_lck->lock_data;
	NTSTATUS status;

	SMB_ASSERT(plock->lock_type != UNLOCK_LOCK);

	if ((plock->start + plock->size - 1 < plock->start) &&
			plock->size != 0) {
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
			return brl_lock_failed(fsp,plock,blocking_lock);
		}
#if ZERO_ZERO
		if (plock->start == 0 && plock->size == 0 &&
				locks[i].size == 0) {
			break;
		}
#endif
	}

	if (!IS_PENDING_LOCK(plock->lock_type)) {
		contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_WINDOWS_BRL);
	}

	/* We can get the Windows lock, now see if it needs to
	   be mapped into a lower level POSIX one, and if so can
	   we get it ? */

	if (!IS_PENDING_LOCK(plock->lock_type) && lp_posix_locking(fsp->conn->params)) {
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
				status = NT_STATUS_FILE_LOCK_CONFLICT;
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
	if (!IS_PENDING_LOCK(plock->lock_type)) {
		contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_WINDOWS_BRL);
	}
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

static NTSTATUS brl_lock_posix(struct messaging_context *msg_ctx,
			       struct byte_range_lock *br_lck,
			       struct lock_struct *plock)
{
	unsigned int i, count, posix_count;
	struct lock_struct *locks = br_lck->lock_data;
	struct lock_struct *tp;
	bool signal_pending_read = False;
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

		/* If we have a pending read lock, a lock downgrade should
		   trigger a lock re-evaluation. */
		if (curr_lock->lock_type == PENDING_READ_LOCK &&
				brl_pending_overlap(plock, curr_lock)) {
			signal_pending_read = True;
		}

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
				return NT_STATUS_FILE_LOCK_CONFLICT;
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
				return NT_STATUS_FILE_LOCK_CONFLICT;
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
	break_oplocks = (!IS_PENDING_LOCK(plock->lock_type) &&
			 posix_count == 0);
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

	if (!IS_PENDING_LOCK(plock->lock_type) && lp_posix_locking(br_lck->fsp->conn->params)) {
		int errno_ret;

		/* The lower layer just needs to attempt to
		   get the system POSIX lock. We've weeded out
		   any conflicts above. */

		if (!set_posix_lock_posix_flavour(br_lck->fsp,
				plock->start,
				plock->size,
				plock->lock_type,
				&errno_ret)) {

			/* We don't know who blocked us. */
			plock->context.smblctx = 0xFFFFFFFFFFFFFFFFLL;

			if (errno_ret == EACCES || errno_ret == EAGAIN) {
				TALLOC_FREE(tp);
				status = NT_STATUS_FILE_LOCK_CONFLICT;
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

	if (signal_pending_read) {
		/* Send unlock messages to any pending read waiters that overlap. */
		for (i=0; i < br_lck->num_locks; i++) {
			struct lock_struct *pend_lock = &locks[i];

			/* Ignore non-pending locks. */
			if (!IS_PENDING_LOCK(pend_lock->lock_type)) {
				continue;
			}

			if (pend_lock->lock_type == PENDING_READ_LOCK &&
					brl_pending_overlap(plock, pend_lock)) {
				DEBUG(10,("brl_lock_posix: sending unlock message to pid %s\n",
					procid_str_static(&pend_lock->context.pid )));

				messaging_send(msg_ctx, pend_lock->context.pid,
					       MSG_SMB_UNLOCK, &data_blob_null);
			}
		}
	}

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
				       struct lock_struct *plock,
				       bool blocking_lock)
{
	VFS_FIND(brl_lock_windows);
	return handle->fns->brl_lock_windows_fn(handle, br_lck, plock,
						blocking_lock);
}

/****************************************************************************
 Lock a range of bytes.
****************************************************************************/

NTSTATUS brl_lock(struct messaging_context *msg_ctx,
		struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		bool blocking_lock,
		uint64_t *psmblctx)
{
	NTSTATUS ret;
	struct lock_struct lock;

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
		ret = SMB_VFS_BRL_LOCK_WINDOWS(br_lck->fsp->conn, br_lck,
					       &lock, blocking_lock);
	} else {
		ret = brl_lock_posix(msg_ctx, br_lck, &lock);
	}

#if ZERO_ZERO
	/* sort the lock list */
	TYPESAFE_QSORT(br_lck->lock_data, (size_t)br_lck->num_locks, lock_compare);
#endif

	/* If we're returning an error, return who blocked us. */
	if (!NT_STATUS_IS_OK(ret) && psmblctx) {
		*psmblctx = lock.context.smblctx;
	}
	return ret;
}

static void brl_delete_lock_struct(struct lock_struct *locks,
				   unsigned num_locks,
				   unsigned del_idx)
{
	if (del_idx >= num_locks) {
		return;
	}
	memmove(&locks[del_idx], &locks[del_idx+1],
		sizeof(*locks) * (num_locks - del_idx - 1));
}

/****************************************************************************
 Unlock a range of bytes - Windows semantics.
****************************************************************************/

bool brl_unlock_windows_default(struct messaging_context *msg_ctx,
			       struct byte_range_lock *br_lck,
			       const struct lock_struct *plock)
{
	unsigned int i, j;
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

		if (IS_PENDING_LOCK(lock->lock_type)) {
			continue;
		}

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

	brl_delete_lock_struct(locks, br_lck->num_locks, i);
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

	/* Send unlock messages to any pending waiters that overlap. */
	for (j=0; j < br_lck->num_locks; j++) {
		struct lock_struct *pend_lock = &locks[j];

		/* Ignore non-pending locks. */
		if (!IS_PENDING_LOCK(pend_lock->lock_type)) {
			continue;
		}

		/* We could send specific lock info here... */
		if (brl_pending_overlap(plock, pend_lock)) {
			DEBUG(10,("brl_unlock: sending unlock message to pid %s\n",
				procid_str_static(&pend_lock->context.pid )));

			messaging_send(msg_ctx, pend_lock->context.pid,
				       MSG_SMB_UNLOCK, &data_blob_null);
		}
	}

	contend_level2_oplocks_end(br_lck->fsp, LEVEL2_CONTEND_WINDOWS_BRL);
	return True;
}

/****************************************************************************
 Unlock a range of bytes - POSIX semantics.
****************************************************************************/

static bool brl_unlock_posix(struct messaging_context *msg_ctx,
			     struct byte_range_lock *br_lck,
			     struct lock_struct *plock)
{
	unsigned int i, j, count;
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
		if (IS_PENDING_LOCK(lock->lock_type) ||
				!brl_same_context(&lock->context, &plock->context)) {
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

	/* Send unlock messages to any pending waiters that overlap. */

	for (j=0; j < br_lck->num_locks; j++) {
		struct lock_struct *pend_lock = &locks[j];

		/* Ignore non-pending locks. */
		if (!IS_PENDING_LOCK(pend_lock->lock_type)) {
			continue;
		}

		/* We could send specific lock info here... */
		if (brl_pending_overlap(plock, pend_lock)) {
			DEBUG(10,("brl_unlock: sending unlock message to pid %s\n",
				procid_str_static(&pend_lock->context.pid )));

			messaging_send(msg_ctx, pend_lock->context.pid,
				       MSG_SMB_UNLOCK, &data_blob_null);
		}
	}

	return True;
}

bool smb_vfs_call_brl_unlock_windows(struct vfs_handle_struct *handle,
				     struct messaging_context *msg_ctx,
				     struct byte_range_lock *br_lck,
				     const struct lock_struct *plock)
{
	VFS_FIND(brl_unlock_windows);
	return handle->fns->brl_unlock_windows_fn(handle, msg_ctx, br_lck,
						  plock);
}

/****************************************************************************
 Unlock a range of bytes.
****************************************************************************/

bool brl_unlock(struct messaging_context *msg_ctx,
		struct byte_range_lock *br_lck,
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
		return SMB_VFS_BRL_UNLOCK_WINDOWS(br_lck->fsp->conn, msg_ctx,
		    br_lck, &lock);
	} else {
		return brl_unlock_posix(msg_ctx, br_lck, &lock);
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


bool smb_vfs_call_brl_cancel_windows(struct vfs_handle_struct *handle,
				     struct byte_range_lock *br_lck,
				     struct lock_struct *plock)
{
	VFS_FIND(brl_cancel_windows);
	return handle->fns->brl_cancel_windows_fn(handle, br_lck, plock);
}

/****************************************************************************
 Remove a particular pending lock.
****************************************************************************/
bool brl_lock_cancel(struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav)
{
	bool ret;
	struct lock_struct lock;

	lock.context.smblctx = smblctx;
	lock.context.pid = pid;
	lock.context.tid = br_lck->fsp->conn->cnum;
	lock.start = start;
	lock.size = size;
	lock.fnum = br_lck->fsp->fnum;
	lock.lock_flav = lock_flav;
	/* lock.lock_type doesn't matter */

	if (lock_flav == WINDOWS_LOCK) {
		ret = SMB_VFS_BRL_CANCEL_WINDOWS(br_lck->fsp->conn, br_lck,
						 &lock);
	} else {
		ret = brl_lock_cancel_default(br_lck, &lock);
	}

	return ret;
}

bool brl_lock_cancel_default(struct byte_range_lock *br_lck,
		struct lock_struct *plock)
{
	unsigned int i;
	struct lock_struct *locks = br_lck->lock_data;

	SMB_ASSERT(plock);

	for (i = 0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &locks[i];

		/* For pending locks we *always* care about the fnum. */
		if (brl_same_context(&lock->context, &plock->context) &&
				lock->fnum == plock->fnum &&
				IS_PENDING_LOCK(lock->lock_type) &&
				lock->lock_flav == plock->lock_flav &&
				lock->start == plock->start &&
				lock->size == plock->size) {
			break;
		}
	}

	if (i == br_lck->num_locks) {
		/* Didn't find it. */
		return False;
	}

	brl_delete_lock_struct(locks, br_lck->num_locks, i);
	br_lck->num_locks -= 1;
	br_lck->modified = True;
	return True;
}

/****************************************************************************
 Remove any locks associated with a open file.
 We return True if this process owns any other Windows locks on this
 fd and so we should not immediately close the fd.
****************************************************************************/

void brl_close_fnum(struct messaging_context *msg_ctx,
		    struct byte_range_lock *br_lck)
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

		if (lock->context.tid == tid && serverid_equal(&lock->context.pid, &pid) &&
				(lock->fnum == fnum)) {
			brl_unlock(msg_ctx,
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

		if (!serverid_equal(&lock->context.pid, &self)) {
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

	if ((br_lck->num_locks == 0) && (br_lck->num_read_oplocks == 0)) {
		/* No locks - delete this entry. */
		NTSTATUS status = dbwrap_record_delete(br_lck->record);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("delete_rec returned %s\n",
				  nt_errstr(status)));
			smb_panic("Could not delete byte range lock entry");
		}
	} else {
		size_t lock_len, data_len;
		TDB_DATA data;
		NTSTATUS status;

		lock_len = br_lck->num_locks * sizeof(struct lock_struct);
		data_len = lock_len + sizeof(br_lck->num_read_oplocks);

		data.dsize = data_len;
		data.dptr = talloc_array(talloc_tos(), uint8_t, data_len);
		SMB_ASSERT(data.dptr != NULL);

		memcpy(data.dptr, br_lck->lock_data, lock_len);
		memcpy(data.dptr + lock_len, &br_lck->num_read_oplocks,
		       sizeof(br_lck->num_read_oplocks));

		status = dbwrap_record_store(br_lck->record, data, TDB_REPLACE);
		TALLOC_FREE(data.dptr);
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
	if (data.dsize % sizeof(struct lock_struct) !=
	    sizeof(br_lck->num_read_oplocks)) {
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
	memcpy(&br_lck->num_read_oplocks, data.dptr + data_len,
	       sizeof(br_lck->num_read_oplocks));
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

	key.dptr = (uint8 *)&fsp->file_id;
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
		struct lock_struct *locks = br_lck->lock_data;
		DEBUG(10,("brl_get_locks_internal: %u current locks on file_id %s\n",
			br_lck->num_locks,
			  file_id_string_tos(&fsp->file_id)));
		for( i = 0; i < br_lck->num_locks; i++) {
			print_lock_struct(i, &locks[i]);
		}
	}

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
		br_lock = talloc(fsp, struct byte_range_lock);
		if (br_lock == NULL) {
			return NULL;
		}

		br_lock->num_read_oplocks = 0;
		br_lock->num_locks = 0;
		br_lock->lock_data = NULL;

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

	if (lp_clustering()) {
		/*
		 * In the cluster case we can't cache the brlock struct
		 * because dbwrap_get_seqnum does not work reliably over
		 * ctdb. Thus we have to throw away the brlock struct soon.
		 */
		talloc_steal(talloc_tos(), br_lock);
	} else {
		/*
		 * Cache the brlock struct, invalidated when the dbwrap_seqnum
		 * changes. See beginning of this routine.
		 */
		TALLOC_FREE(fsp->brlock_rec);
		fsp->brlock_rec = br_lock;
		fsp->brlock_seqnum = dbwrap_get_seqnum(brlock_db);
	}

	return br_lock;
}

struct brl_revalidate_state {
	ssize_t array_size;
	uint32 num_pids;
	struct server_id *pids;
};

/*
 * Collect PIDs of all processes with pending entries
 */

static void brl_revalidate_collect(struct file_id id, struct server_id pid,
				   enum brl_type lock_type,
				   enum brl_flavour lock_flav,
				   br_off start, br_off size,
				   void *private_data)
{
	struct brl_revalidate_state *state =
		(struct brl_revalidate_state *)private_data;

	if (!IS_PENDING_LOCK(lock_type)) {
		return;
	}

	add_to_large_array(state, sizeof(pid), (void *)&pid,
			   &state->pids, &state->num_pids,
			   &state->array_size);
}

/*
 * qsort callback to sort the processes
 */

static int compare_procids(const void *p1, const void *p2)
{
	const struct server_id *i1 = (const struct server_id *)p1;
	const struct server_id *i2 = (const struct server_id *)p2;

	if (i1->pid < i2->pid) return -1;
	if (i1->pid > i2->pid) return 1;
	return 0;
}

/*
 * Send a MSG_SMB_UNLOCK message to all processes with pending byte range
 * locks so that they retry. Mainly used in the cluster code after a node has
 * died.
 *
 * Done in two steps to avoid double-sends: First we collect all entries in an
 * array, then qsort that array and only send to non-dupes.
 */

void brl_revalidate(struct messaging_context *msg_ctx,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data)
{
	struct brl_revalidate_state *state;
	uint32 i;
	struct server_id last_pid;

	if (!(state = talloc_zero(NULL, struct brl_revalidate_state))) {
		DEBUG(0, ("talloc failed\n"));
		return;
	}

	brl_forall(brl_revalidate_collect, state);

	if (state->array_size == -1) {
		DEBUG(0, ("talloc failed\n"));
		goto done;
	}

	if (state->num_pids == 0) {
		goto done;
	}

	TYPESAFE_QSORT(state->pids, state->num_pids, compare_procids);

	ZERO_STRUCT(last_pid);

	for (i=0; i<state->num_pids; i++) {
		if (serverid_equal(&last_pid, &state->pids[i])) {
			/*
			 * We've seen that one already
			 */
			continue;
		}

		messaging_send(msg_ctx, state->pids[i], MSG_SMB_UNLOCK,
			       &data_blob_null);
		last_pid = state->pids[i];
	}

 done:
	TALLOC_FREE(state);
	return;
}

bool brl_cleanup_disconnected(struct file_id fid, uint64_t open_persistent_id)
{
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA key, val;
	struct db_record *rec;
	struct lock_struct *lock;
	unsigned n, num;
	NTSTATUS status;

	key = make_tdb_data((void*)&fid, sizeof(fid));

	rec = dbwrap_fetch_locked(brlock_db, frame, key);
	if (rec == NULL) {
		DEBUG(5, ("brl_cleanup_disconnected: failed to fetch record "
			  "for file %s\n", file_id_string(frame, &fid)));
		goto done;
	}

	val = dbwrap_record_get_value(rec);
	lock = (struct lock_struct*)val.dptr;
	num = val.dsize / sizeof(struct lock_struct);
	if (lock == NULL) {
		DEBUG(10, ("brl_cleanup_disconnected: no byte range locks for "
			   "file %s\n", file_id_string(frame, &fid)));
		ret = true;
		goto done;
	}

	for (n=0; n<num; n++) {
		struct lock_context *ctx = &lock[n].context;

		if (!server_id_is_disconnected(&ctx->pid)) {
			DEBUG(5, ("brl_cleanup_disconnected: byte range lock "
				  "%s used by server %s, do not cleanup\n",
				  file_id_string(frame, &fid),
				  server_id_str(frame, &ctx->pid)));
			goto done;
		}

		if (ctx->smblctx != open_persistent_id)	{
			DEBUG(5, ("brl_cleanup_disconnected: byte range lock "
				  "%s expected smblctx %llu but found %llu"
				  ", do not cleanup\n",
				  file_id_string(frame, &fid),
				  (unsigned long long)open_persistent_id,
				  (unsigned long long)ctx->smblctx));
			goto done;
		}
	}

	status = dbwrap_record_delete(rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("brl_cleanup_disconnected: failed to delete record "
			  "for file %s from %s, open %llu: %s\n",
			  file_id_string(frame, &fid), dbwrap_name(brlock_db),
			  (unsigned long long)open_persistent_id,
			  nt_errstr(status)));
		goto done;
	}

	DEBUG(10, ("brl_cleanup_disconnected: "
		   "file %s cleaned up %u entries from open %llu\n",
		   file_id_string(frame, &fid), num,
		   (unsigned long long)open_persistent_id));

	ret = true;
done:
	talloc_free(frame);
	return ret;
}
