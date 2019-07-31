/*
 * Convert NFSv4 acls stored per http://www.suse.de/~agruen/nfs4acl/ to NT acls and vice versa.
 *
 * Copyright (C) Jiri Sasek, 2007
 * based on the foobar.c module which is copyrighted by Volker Lendecke
 * based on pvfs_acl_nfs4.c  Copyright (C) Andrew Tridgell 2006
 *
 * based on vfs_fake_acls:
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Andrew Bartlett, 2002,2012
 * Copyright (C) Ralph Boehme 2017
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

#ifndef __NFS4ACL_XATTR_NDR_H__
#define __NFS4ACL_XATTR_NDR_H__

struct SMB4ACL_T;

NTSTATUS nfs4acl_ndr_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl);

NTSTATUS nfs4acl_smb4acl_to_ndr_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smbacl,
				     DATA_BLOB *blob);

#endif /* _VFS_NFS4ACL_XATTR_NDR_H */
