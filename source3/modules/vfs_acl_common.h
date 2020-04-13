/*
 * Store Windows ACLs in data store - common functions.
 *
 * Copyright (C) Volker Lendecke, 2008
 * Copyright (C) Jeremy Allison, 2009
 * Copyright (C) Ralph Böhme, 2016
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

#ifndef __VFS_ACL_COMMON_H__
#define __VFS_ACL_COMMON_H__

#include "smbd/proto.h"

struct acl_common_config {
	bool ignore_system_acls;
	enum default_acl_style default_acl_style;
};

bool init_acl_common_config(vfs_handle_struct *handle,
			    const char *module_name);

int rmdir_acl_common(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname);
int unlink_acl_common(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags);
int chmod_acl_module_common(struct vfs_handle_struct *handle,
			    const struct smb_filename *smb_fname,
			    mode_t mode);
int fchmod_acl_module_common(struct vfs_handle_struct *handle,
			     struct files_struct *fsp, mode_t mode);
int chmod_acl_acl_module_common(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				mode_t mode);
NTSTATUS get_nt_acl_common_at(
	NTSTATUS (*get_acl_blob_at_fn)(TALLOC_CTX *ctx,
				    vfs_handle_struct *handle,
				    struct files_struct *dirfsp,
				    const struct smb_filename *smb_fname,
				    DATA_BLOB *pblob),
	vfs_handle_struct *handle,
	struct files_struct *dirfsp,
	const struct smb_filename *smb_fname_in,
	uint32_t security_info,
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **ppdesc);

NTSTATUS fget_nt_acl_common(
	NTSTATUS (*fget_acl_blob_fn)(TALLOC_CTX *ctx,
				    vfs_handle_struct *handle,
				    files_struct *fsp,
				    DATA_BLOB *pblob),
	vfs_handle_struct *handle,
	files_struct *fsp,
	uint32_t security_info,
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **ppdesc);

NTSTATUS fset_nt_acl_common(
	NTSTATUS (*fget_acl_blob_fn)(TALLOC_CTX *ctx,
				    vfs_handle_struct *handle,
				    files_struct *fsp,
				    DATA_BLOB *pblob),
	NTSTATUS (*store_acl_blob_fsp_fn)(vfs_handle_struct *handle,
					  files_struct *fsp,
					  DATA_BLOB *pblob),
	const char *module_name,
	vfs_handle_struct *handle, files_struct *fsp,
        uint32_t security_info_sent,
	const struct security_descriptor *orig_psd);



#endif
