/*
 * Copyright (c) Björn Jacke 2010
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
#include "transfer_file.h"
#include "smbprofile.h"

#define MODULE "crossrename"
static off_t module_sizelimit;

static int crossrename_connect(
                struct vfs_handle_struct *  handle,
                const char *                service,
                const char *                user)
{
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	module_sizelimit = (off_t) lp_parm_int(SNUM(handle->conn),
					MODULE, "sizelimit", 20);
	/* convert from MiB to byte: */
	module_sizelimit *= 1048576;

	return 0;
}

/*********************************************************
 For rename across filesystems initial Patch from Warren Birnbaum
 <warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

static NTSTATUS copy_reg(vfs_handle_struct *handle,
			 struct files_struct *srcfsp,
			 const struct smb_filename *source,
			 struct files_struct *dstfsp,
			 const struct smb_filename *dest)
{
	NTSTATUS status;
	struct smb_filename *full_fname_src = NULL;
	struct smb_filename *full_fname_dst = NULL;
	int ret;

	if (!VALID_STAT(source->st)) {
		status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto out;
	}
	if (!S_ISREG(source->st.st_ex_mode)) {
		status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto out;
	}

	if (source->st.st_ex_size > module_sizelimit) {
		DBG_INFO("%s: size of %s larger than sizelimit (%lld > %lld), "
			 "rename prohibited\n",
			MODULE,
			source->base_name,
			(long long)source->st.st_ex_size,
			(long long)module_sizelimit);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	full_fname_src = full_path_from_dirfsp_atname(talloc_tos(),
						      srcfsp,
						      source);
	if (full_fname_src == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	full_fname_dst = full_path_from_dirfsp_atname(talloc_tos(),
						      dstfsp,
						      dest);
	if (full_fname_dst == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = SMB_VFS_NEXT_UNLINKAT(handle,
				    dstfsp,
				    dest,
				    0);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	/*
	 * copy_internals() takes attribute values from the NTrename call.
	 *
	 * From MS-CIFS:
	 *
	 * "If the attribute is 0x0000, then only normal files are renamed.
	 * If the system file or hidden attributes are specified, then the
	 * rename is inclusive of both special types."
	 */
	status = copy_internals(talloc_tos(),
				handle->conn,
				NULL,
				srcfsp, /* src_dirfsp */
				full_fname_src,
				dstfsp, /* dst_dirfsp */
				full_fname_dst,
				FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	ret = SMB_VFS_NEXT_UNLINKAT(handle,
				    srcfsp,
				    source,
				    0);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

  out:

	TALLOC_FREE(full_fname_src);
	TALLOC_FREE(full_fname_dst);
	return status;
}

static int crossrename_renameat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	int result = -1;

	START_PROFILE(syscall_renameat);

	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		errno = ENOENT;
		goto out;
	}

	result = SMB_VFS_NEXT_RENAMEAT(handle,
				       srcfsp,
				       smb_fname_src,
				       dstfsp,
				       smb_fname_dst);

	if ((result == -1) && (errno == EXDEV)) {
		/* Rename across filesystems needed. */
		NTSTATUS status = copy_reg(handle,
					   srcfsp,
					   smb_fname_src,
					   dstfsp,
					   smb_fname_dst);
		if (!NT_STATUS_IS_OK(status)) {
			errno = map_errno_from_nt_status(status);
			result = -1;
		}
	}

 out:
	END_PROFILE(syscall_renameat);
	return result;
}


static struct vfs_fn_pointers vfs_crossrename_fns = {
	.connect_fn = crossrename_connect,
	.renameat_fn = crossrename_renameat
};

static_decl_vfs;
NTSTATUS vfs_crossrename_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, MODULE,
				&vfs_crossrename_fns);
}

