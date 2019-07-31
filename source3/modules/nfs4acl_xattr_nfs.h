/*
 * Copyright (C) Ralph Boehme 2018
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
 *
 */

#ifndef __NFS4ACL_XATTR_NFS_H__
#define __NFS4ACL_XATTR_NFS_H__

#define NFS4ACL_NFS_XATTR_NAME "system.nfs4_acl"

struct SMB4ACL_T;

NTSTATUS nfs4acl_nfs_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl);

NTSTATUS nfs4acl_smb4acl_to_nfs_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smbacl,
				     DATA_BLOB *blob);

#endif /* __NFS4ACL_XATTR_NFS_H__ */
