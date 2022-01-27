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

/*
 * SMB2 POSIX create context return details.
 */
DATA_BLOB smb2_posix_cc_info(TALLOC_CTX *mem_ctx,
				connection_struct *conn,
				uint32_t reparse_tag,
				const SMB_STRUCT_STAT *psbuf)
{
	DATA_BLOB ret_blob = data_blob_null;
	struct dom_sid sid_owner;
	struct dom_sid sid_group;
	size_t owner_sid_size = 0;
	size_t group_sid_size = 0;
	size_t b_size = 12;

	uid_to_sid(&sid_owner, psbuf->st_ex_uid);
	owner_sid_size = ndr_size_dom_sid(&sid_owner, 0);
	if (b_size + owner_sid_size < b_size) {
		return data_blob_null;
	}
	b_size += owner_sid_size;

	gid_to_sid(&sid_group, psbuf->st_ex_gid);
	group_sid_size = ndr_size_dom_sid(&sid_group, 0);
	if (b_size + group_sid_size < b_size) {
		return data_blob_null;
	}
	b_size += group_sid_size;

	ret_blob = data_blob_talloc(mem_ctx,
				    NULL,
				    b_size);
	if (ret_blob.data == NULL) {
		return data_blob_null;
	}

	/* number of hard links */
	PUSH_LE_U32(ret_blob.data, 0, psbuf->st_ex_nlink);

	/* Reparse tag if FILE_FLAG_REPARSE is set, else zero. */
	PUSH_LE_U32(ret_blob.data, 4, reparse_tag);

	/*
	 * Remove type info from mode, leaving only the
	 * permissions and setuid/gid bits.
	 */
	PUSH_LE_U32(ret_blob.data,
		    8,
		    unix_perms_to_wire(psbuf->st_ex_mode & ~S_IFMT));

	/* Now add in the owner and group sids. */
	sid_linearize(ret_blob.data + 12,
		      b_size - 12,
		      &sid_owner);
	sid_linearize(ret_blob.data + 12 + owner_sid_size,
		      b_size - owner_sid_size - 12,
		      &sid_group);
	return ret_blob;
}

/*
 * SMB2 POSIX info level.
 */
DATA_BLOB store_smb2_posix_info(TALLOC_CTX *mem_ctx,
				connection_struct *conn,
				const SMB_STRUCT_STAT *psbuf,
				uint32_t reparse_tag,
				uint32_t dos_attributes)
{
	uint64_t file_id = SMB_VFS_FS_FILE_ID(conn, psbuf);
	DATA_BLOB ret_blob = data_blob_null;
	DATA_BLOB cc = smb2_posix_cc_info(mem_ctx,
					conn,
					reparse_tag,
					psbuf);
	if (cc.data == NULL) {
		return data_blob_null;
	}

	if (cc.length + 68 < 68) {
		data_blob_free(&cc);
		return data_blob_null;
	}

	ret_blob = data_blob_talloc(mem_ctx,
				NULL,
				cc.length + 68);
	if (ret_blob.data == NULL) {
		data_blob_free(&cc);
		return data_blob_null;
	}

	/* Timestamps. */

	/* Birth (creation) time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)ret_blob.data+0,
			       psbuf->st_ex_btime);
	/* Access time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)ret_blob.data+8,
			       psbuf->st_ex_atime);
	/* Last write time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)ret_blob.data+16,
			       psbuf->st_ex_mtime);
	/* Change time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)ret_blob.data+24,
			       psbuf->st_ex_ctime);

	/* File size 64 Bit */
	SOFF_T(ret_blob.data,32, get_file_size_stat(psbuf));

	/* Number of bytes used on disk - 64 Bit */
	SOFF_T(ret_blob.data,40,SMB_VFS_GET_ALLOC_SIZE(conn,NULL,psbuf));

	/* DOS attributes */
	if (S_ISREG(psbuf->st_ex_mode)) {
		PUSH_LE_U32(ret_blob.data, 48, dos_attributes);
	} else if (S_ISDIR(psbuf->st_ex_mode)) {
		PUSH_LE_U32(ret_blob.data,
			    48,
			    dos_attributes|FILE_ATTRIBUTE_DIRECTORY);
	} else {
		/*
		 * All non-directory or regular files are reported
		 * as reparse points. Client may or may not be able
		 * to access these.
		 */
		PUSH_LE_U32(ret_blob.data,
			    48,
			    FILE_ATTRIBUTE_REPARSE_POINT);
	}

	/* Add the inode and dev (16 bytes). */
	PUSH_LE_U64(ret_blob.data, 52, file_id);
	PUSH_LE_U64(ret_blob.data, 60, psbuf->st_ex_dev);

	/*
	 * Append a POSIX create context (variable bytes).
	 */
	memcpy(ret_blob.data + 68, cc.data, cc.length);
	data_blob_free(&cc);
	return ret_blob;
}
