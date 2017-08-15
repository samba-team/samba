/*
 * VFS module to make a share read only for a specialfied time period
 *
 * Copyright (C) 2017, Li Dan
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "libcli/security/security.h"
#include "getdate.h"

#define MODULE_NAME "retention"
static NTSTATUS vfs_retention_create_file(vfs_handle_struct * handle,
					  struct smb_request *req,
					  uint16_t root_dir_fid,
					  struct smb_filename *smb_fname,
					  uint32_t access_mask,
					  uint32_t share_access,
					  uint32_t create_disposition,
					  uint32_t create_options,
					  uint32_t file_attributes,
					  uint32_t oplock_request,
					  struct smb2_lease *lease,
					  uint64_t allocation_size,
					  uint32_t private_flags,
					  struct security_descriptor *sd,
					  struct ea_list *ea_list,
					  files_struct ** result,
					  int *pinfo,
					  const struct smb2_create_blobs
					  *in_context_blobs, struct smb2_create_blobs
					  *out_context_blobs)
{
	bool readonly = false;
	const uint32_t write_access_flags =
	    FILE_WRITE_DATA | FILE_APPEND_DATA |
	    FILE_WRITE_ATTRIBUTES | DELETE_ACCESS |
	    WRITE_DAC_ACCESS | WRITE_OWNER_ACCESS;
	NTSTATUS status;

	const char **period = lp_parm_string_list(SNUM(handle->conn),
						  (handle->
						   param ? handle->param :
						   MODULE_NAME),
						  "period", NULL);
	if (!period) {

		/* read only forever */
		readonly = true;
	}

	if (period && period[0] && period[1]) {

		time_t current_time = time(NULL);
		time_t begin_period = get_date(period[0], &current_time);
		time_t end_period = get_date(period[1], &current_time);
		if ((current_time >= begin_period)
		    && (current_time <= end_period)) {
			readonly = true;
		}
	}

	if (readonly && (access_mask & write_access_flags)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status =
	    SMB_VFS_NEXT_CREATE_FILE(handle, req, root_dir_fid, smb_fname,
				     access_mask, share_access,
				     create_disposition, create_options,
				     file_attributes, oplock_request, lease,
				     allocation_size, private_flags, sd,
				     ea_list, result, pinfo, in_context_blobs,
				     out_context_blobs);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (readonly && ((*result)->access_mask & write_access_flags)) {
		close_file(req, *result, NORMAL_CLOSE);
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static struct vfs_fn_pointers vfs_retention_fns = {
	.create_file_fn = vfs_retention_create_file,
};

NTSTATUS vfs_retention_init(TALLOC_CTX *);
NTSTATUS vfs_retention_init(TALLOC_CTX * ctx)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, MODULE_NAME,
			       &vfs_retention_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	return ret;
}
