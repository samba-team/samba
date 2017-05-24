/*
   Unix SMB/Netbios implementation.
   VFS module to get and set posix acl through xattr
   Copyright (c) 2013 Anand Avati <avati@redhat.com>
   Copyright (c) 2016 Yan, Zheng <zyan@redhat.com>

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

#ifndef __POSIXACL_XATTR_H__
#define __POSIXACL_XATTR_H__

SMB_ACL_T posixacl_xattr_acl_get_file(vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname,
				      SMB_ACL_TYPE_T type,
				      TALLOC_CTX *mem_ctx);

SMB_ACL_T posixacl_xattr_acl_get_fd(vfs_handle_struct *handle,
				    files_struct *fsp,
				    TALLOC_CTX *mem_ctx);

int posixacl_xattr_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T type,
				SMB_ACL_T theacl);

int posixacl_xattr_acl_set_fd(vfs_handle_struct *handle,
			      files_struct *fsp,
			      SMB_ACL_T theacl);

int posixacl_xattr_acl_delete_def_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname);
#endif
