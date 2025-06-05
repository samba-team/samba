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
#include "source3/modules/util_reparse.h"
#include "libcli/smb/reparse.h"

static NTSTATUS reparse_buffer_parse_posix_type(uint32_t reparse_tag,
						uint8_t *data,
						uint32_t len,
						mode_t *type)
{
	struct reparse_data_buffer *reparse = NULL;
	NTSTATUS status;

	if (reparse_tag == IO_REPARSE_TAG_SYMLINK) {
		*type = S_IFLNK;
		return NT_STATUS_OK;
	}
	if (reparse_tag != IO_REPARSE_TAG_NFS) {
		/*
		 * Clients can create reparse points with arbitrary tags, return
		 * anything that is not a NFS one (or symlink) as S_IFREG.
		 */
		DBG_INFO("Unhandled NFS reparse tag: 0x%" PRIx32 "\n",
			 reparse_tag);
		*type = S_IFREG;
		return NT_STATUS_OK;
	}

	reparse = talloc_zero(talloc_tos(), struct reparse_data_buffer);
	if (reparse == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	status = reparse_data_buffer_parse(reparse, reparse, data, len);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(reparse);
		return status;
	}

	switch (reparse->parsed.nfs.type) {
	case NFS_SPECFILE_CHR:
		*type = S_IFCHR;
		break;
	case NFS_SPECFILE_BLK:
		*type = S_IFBLK;
		break;
	case NFS_SPECFILE_FIFO:
		*type = S_IFIFO;
		break;
	case NFS_SPECFILE_SOCK:
		*type = S_IFSOCK;
		break;
	default:
		DBG_ERR("Unhandled NFS reparse type: 0x%" PRIx64 "\n",
			reparse->parsed.nfs.type);
		TALLOC_FREE(reparse);
		return NT_STATUS_REPARSE_POINT_NOT_RESOLVED;
	}

	TALLOC_FREE(reparse);
	return status;
}

NTSTATUS smb3_file_posix_information_init(
	connection_struct *conn,
	const struct smb_filename *smb_fname,
	uint32_t dos_attributes,
	struct smb3_file_posix_information *dst)
{
	const struct stat_ex *st = &smb_fname->st;
	mode_t mode = st->st_ex_mode;
	uint32_t reparse_tag = 0;
	NTSTATUS status;

	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
		break;
	default:
		/*
		 * All non-directory or regular files are reported
		 * as reparse points. Client may or may not be able
		 * to access these. This should already be set by
		 * fdos_mode(), assert this.
		 */
		SMB_ASSERT(dos_attributes & FILE_ATTRIBUTE_REPARSE_POINT);
		break;
	}

	if (dos_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		uint8_t *reparse_data = NULL;
		uint32_t reparse_len;
		mode_t type = S_IFREG;

		status = fsctl_get_reparse_point(smb_fname->fsp,
						 talloc_tos(),
						 &reparse_tag,
						 &reparse_data,
						 UINT32_MAX,
						 &reparse_len);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not get reparse point for %s: %s\n",
				  smb_fname_str_dbg(smb_fname),
				  nt_errstr(status));
			return status;
		}

		status = reparse_buffer_parse_posix_type(reparse_tag,
							 reparse_data,
							 reparse_len,
							 &type);
		TALLOC_FREE(reparse_data);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not parse reparse data for %s: %s\n",
				  smb_fname_str_dbg(smb_fname),
				  nt_errstr(status));
			return status;
		}

		/*
		 * Remove the type info we got via stat() and use what
		 * we got from the reparse point.
		 */
		mode &= ~S_IFMT;
		mode |= type;
	}

	*dst = (struct smb3_file_posix_information) {
		.end_of_file = get_file_size_stat(st),
		.allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn,NULL,st),
		.inode = SMB_VFS_FS_FILE_ID(conn, st),
		.device = st->st_ex_dev,
		.creation_time = unix_timespec_to_nt_time(st->st_ex_btime),
		.last_access_time = unix_timespec_to_nt_time(st->st_ex_atime),
		.last_write_time = unix_timespec_to_nt_time(st->st_ex_mtime),
		.change_time = unix_timespec_to_nt_time(st->st_ex_ctime),
		.file_attributes = dos_attributes,
		.cc.nlinks = st->st_ex_nlink,
		.cc.reparse_tag = reparse_tag,
		.cc.posix_mode = unix_mode_to_wire(mode),
		.cc.owner = global_sid_NULL,
		.cc.group = global_sid_NULL,
	};

	if (st->st_ex_uid != (uid_t)-1) {
		uid_to_sid(&dst->cc.owner, st->st_ex_uid);
	}
	if (st->st_ex_gid != (uid_t)-1) {
		gid_to_sid(&dst->cc.group, st->st_ex_gid);
	}
	return NT_STATUS_OK;
}
