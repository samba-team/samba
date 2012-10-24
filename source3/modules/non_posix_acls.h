/*
   Unix SMB/CIFS implementation.
   Access Control List handling
   Copyright (C) Andrew Bartlett 2012.

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

int non_posix_sys_acl_blob_get_file_helper(vfs_handle_struct *handle,
					   const char *path_p,
					   DATA_BLOB acl_as_blob,
					   TALLOC_CTX *mem_ctx,
					   DATA_BLOB *blob);
int non_posix_sys_acl_blob_get_fd_helper(vfs_handle_struct *handle,
					 files_struct *fsp,
					 DATA_BLOB acl_as_blob,
					 TALLOC_CTX *mem_ctx,
					 DATA_BLOB *blob);
