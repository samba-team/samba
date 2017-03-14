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
	if (fsp->oplock_type == LEASE_OPLOCK) {
		return fsp->lease->lease.lease_state;
	}
	return map_oplock_to_lease_type(fsp->oplock_type);
}
