/*
   Unix SMB/CIFS implementation.
   Lease utility functions

   Copyright (C) Jeremy Allison 2017.
   Copyright (C) Stefan (metze) Metzmacher 2017.

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

#define DBGC_CLASS DBGC_LOCKING
#include "includes.h"
#include "../librpc/gen_ndr/open_files.h"
#include "locking/proto.h"
#include "smbd/globals.h"
#include "locking/leases_db.h"

uint32_t map_oplock_to_lease_type(uint16_t op_type)
{
	uint32_t ret;

	switch(op_type) {
	case BATCH_OPLOCK:
	case BATCH_OPLOCK|EXCLUSIVE_OPLOCK:
		ret = SMB2_LEASE_READ|SMB2_LEASE_WRITE|SMB2_LEASE_HANDLE;
		break;
	case EXCLUSIVE_OPLOCK:
		ret = SMB2_LEASE_READ|SMB2_LEASE_WRITE;
		break;
	case LEVEL_II_OPLOCK:
		ret = SMB2_LEASE_READ;
		break;
	default:
		ret = SMB2_LEASE_NONE;
		break;
	}
	return ret;
}

uint32_t fsp_lease_type(struct files_struct *fsp)
{
	NTSTATUS status;

	if (fsp->oplock_type != LEASE_OPLOCK) {
		uint32_t type = map_oplock_to_lease_type(fsp->oplock_type);
		return type;
	}

	status = leases_db_get_current_state(
		fsp_client_guid(fsp),
		&fsp->lease->lease.lease_key,
		&fsp->leases_db_seqnum,
		&fsp->lease_type);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("leases_db_get_current_state failed: %s\n",
			  nt_errstr(status));
		fsp->lease_type = 0; /* no lease */
	}

	return fsp->lease_type;
}

static uint32_t lease_type_is_exclusive(uint32_t lease_type)
{
	if ((lease_type & (SMB2_LEASE_READ | SMB2_LEASE_WRITE)) ==
	    (SMB2_LEASE_READ | SMB2_LEASE_WRITE)) {
		return true;
	}

	return false;
}

bool fsp_lease_type_is_exclusive(struct files_struct *fsp)
{
	uint32_t lease_type = fsp_lease_type(fsp);

	return lease_type_is_exclusive(lease_type);
}

const struct GUID *fsp_client_guid(const files_struct *fsp)
{
	return &fsp->conn->sconn->client->global->client_guid;
}
