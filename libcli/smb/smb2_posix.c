/*
 * Unix SMB/CIFS implementation.
 *
 * SMB2 Posix context handling
 *
 * Copyright (C) Jeremy Allison 2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "libcli/smb/smb2_posix.h"
#include "libcli/smb/smb2_constants.h"
#include "lib/util/byteorder.h"

NTSTATUS make_smb2_posix_create_ctx(
	TALLOC_CTX *mem_ctx,
	struct smb2_create_blobs **crb,
	mode_t mode)
{
	struct smb2_create_blobs *cblobs = NULL;
	uint8_t linear_mode[4];
	DATA_BLOB blob = { .data=linear_mode, .length=sizeof(linear_mode) };
	NTSTATUS status;

	cblobs = talloc_zero(mem_ctx, struct smb2_create_blobs);
	if (cblobs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	SIVAL(&linear_mode,0, unix_perms_to_wire(mode & ~S_IFMT));

	status = smb2_create_blob_add(
		cblobs, cblobs, SMB2_CREATE_TAG_POSIX, blob);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(cblobs);
		return status;
	}
	*crb = cblobs;
	return NT_STATUS_OK;
}
