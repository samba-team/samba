/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup, plus a whole lot more.

   Copyright (C) Jeremy Allison   2006

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

#ifndef _LOCKING_H
#define _LOCKING_H

/* passed to br lock code - the UNLOCK_LOCK should never be stored into the tdb
   and is used in calculating POSIX unlock ranges only. We differentiate between
   PENDING read and write locks to allow posix lock downgrades to trigger a lock
   re-evaluation. */

enum brl_type {READ_LOCK, WRITE_LOCK, UNLOCK_LOCK};
enum brl_flavour {WINDOWS_LOCK = 0, POSIX_LOCK = 1};

#include "librpc/gen_ndr/server_id.h"
#include "librpc/gen_ndr/misc.h"

/* This contains elements that differentiate locks. The smbpid is a
   client supplied pid, and is essentially the locking context for
   this client */

struct lock_context {
	uint64_t smblctx;
	uint32_t tid;
	struct server_id pid;
};

struct files_struct;

#include "lib/file_id.h"

struct byte_range_lock;
typedef uint64_t br_off;

/* Internal structure in brlock.tdb.
   The data in brlock records is an unsorted linear array of these
   records.  It is unnecessary to store the count as tdb provides the
   size of the record */

struct lock_struct {
	struct lock_context context;
	br_off start;
	br_off size;
	uint64_t fnum;
	enum brl_type lock_type;
	enum brl_flavour lock_flav;
};

struct smbd_lock_element {
	struct GUID req_guid;
	uint64_t smblctx;
	enum brl_type brltype;
	uint64_t offset;
	uint64_t count;
};

struct share_mode_lock {
	struct share_mode_data *data;
};

#endif /* _LOCKING_H_ */
