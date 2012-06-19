 /*
   Trivial Database 2: traverse function.
   Copyright (C) Rusty Russell 2010

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
#include "private.h"
#include <ccan/likely/likely.h>

_PUBLIC_ int64_t ntdb_traverse_(struct ntdb_context *ntdb,
		      int (*fn)(struct ntdb_context *,
				NTDB_DATA, NTDB_DATA, void *),
		      void *p)
{
	enum NTDB_ERROR ecode;
	struct traverse_info tinfo;
	NTDB_DATA k, d;
	int64_t count = 0;

	k.dptr = NULL;
	for (ecode = first_in_hash(ntdb, &tinfo, &k, &d.dsize);
	     ecode == NTDB_SUCCESS;
	     ecode = next_in_hash(ntdb, &tinfo, &k, &d.dsize)) {
		d.dptr = k.dptr + k.dsize;

		count++;
		if (fn && fn(ntdb, k, d, p)) {
			ntdb->free_fn(k.dptr, ntdb->alloc_data);
			return count;
		}
		ntdb->free_fn(k.dptr, ntdb->alloc_data);
	}

	if (ecode != NTDB_ERR_NOEXIST) {
		return NTDB_ERR_TO_OFF(ecode);
	}
	return count;
}

_PUBLIC_ enum NTDB_ERROR ntdb_firstkey(struct ntdb_context *ntdb, NTDB_DATA *key)
{
	struct traverse_info tinfo;

	return first_in_hash(ntdb, &tinfo, key, NULL);
}

/* We lock twice, not very efficient.  We could keep last key & tinfo cached. */
_PUBLIC_ enum NTDB_ERROR ntdb_nextkey(struct ntdb_context *ntdb, NTDB_DATA *key)
{
	struct traverse_info tinfo;
	struct hash_info h;
	struct ntdb_used_record rec;

	tinfo.prev = find_and_lock(ntdb, *key, F_RDLCK, &h, &rec, &tinfo);
	ntdb->free_fn(key->dptr, ntdb->alloc_data);
	if (NTDB_OFF_IS_ERR(tinfo.prev)) {
		return NTDB_OFF_TO_ERR(tinfo.prev);
	}
	ntdb_unlock_hashes(ntdb, h.hlock_start, h.hlock_range, F_RDLCK);

	return next_in_hash(ntdb, &tinfo, key, NULL);
}

static int wipe_one(struct ntdb_context *ntdb,
		    NTDB_DATA key, NTDB_DATA data, enum NTDB_ERROR *ecode)
{
	*ecode = ntdb_delete(ntdb, key);
	return (*ecode != NTDB_SUCCESS);
}

_PUBLIC_ enum NTDB_ERROR ntdb_wipe_all(struct ntdb_context *ntdb)
{
	enum NTDB_ERROR ecode;
	int64_t count;

	ecode = ntdb_allrecord_lock(ntdb, F_WRLCK, NTDB_LOCK_WAIT, false);
	if (ecode != NTDB_SUCCESS)
		return ecode;

	/* FIXME: Be smarter. */
	count = ntdb_traverse(ntdb, wipe_one, &ecode);
	if (count < 0)
		ecode = NTDB_OFF_TO_ERR(count);
	ntdb_allrecord_unlock(ntdb, F_WRLCK);
	return ecode;
}
