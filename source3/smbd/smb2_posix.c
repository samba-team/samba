/*
   Unix SMB/CIFS implementation.
   SMB2 POSIX code.
   Copyright (C) Jeremy Allison                 2022

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

#include "includes.h"
#include "smbd/smbd.h"
#include "passdb/lookup_sid.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/smb3posix.h"
#include "libcli/security/security.h"

void smb3_file_posix_information_init(
	connection_struct *conn,
	const struct stat_ex *st,
	uint32_t reparse_tag,
	uint32_t dos_attributes,
	struct smb3_file_posix_information *dst)
{
	*dst = (struct smb3_file_posix_information) {
		.end_of_file = get_file_size_stat(st),
		.allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn,NULL,st),
		.inode = SMB_VFS_FS_FILE_ID(conn, st),
		.device = st->st_ex_dev,
		.creation_time = unix_timespec_to_nt_time(st->st_ex_btime),
		.last_access_time = unix_timespec_to_nt_time(st->st_ex_atime),
		.last_write_time = unix_timespec_to_nt_time(st->st_ex_mtime),
		.change_time = unix_timespec_to_nt_time(st->st_ex_ctime),
		.cc.nlinks = st->st_ex_nlink,
		.cc.reparse_tag = reparse_tag,
		.cc.posix_mode = unix_mode_to_wire(st->st_ex_mode),
		.cc.owner = global_sid_NULL,
		.cc.group = global_sid_NULL,
	};

	if (st->st_ex_uid != (uid_t)-1) {
		uid_to_sid(&dst->cc.owner, st->st_ex_uid);
	}
	if (st->st_ex_gid != (uid_t)-1) {
		gid_to_sid(&dst->cc.group, st->st_ex_gid);
	}

	switch (st->st_ex_mode & S_IFMT) {
	case S_IFREG:
		dst->file_attributes = dos_attributes;
		break;
	case S_IFDIR:
		dst->file_attributes = dos_attributes | FILE_ATTRIBUTE_DIRECTORY;
		break;
	default:
		/*
		 * All non-directory or regular files are reported
		 * as reparse points. Client may or may not be able
		 * to access these.
		 */
		dst->file_attributes = FILE_ATTRIBUTE_REPARSE_POINT;
		break;
	}
}
