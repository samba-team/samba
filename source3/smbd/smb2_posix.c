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
#include "libcli/security/security.h"

/*
 * SMB2 POSIX create context return details.
 */
ssize_t smb2_posix_cc_info(
	connection_struct *conn,
	uint32_t reparse_tag,
	const SMB_STRUCT_STAT *psbuf,
	const struct dom_sid *owner,
	const struct dom_sid *group,
	uint8_t *buf,
	size_t buflen)
{
	size_t owner_sid_size = ndr_size_dom_sid(owner, 0);
	size_t group_sid_size = ndr_size_dom_sid(group, 0);
	size_t b_size = 12;

	owner_sid_size = ndr_size_dom_sid(owner, 0);
	if (b_size + owner_sid_size < b_size) {
		return -1;
	}
	b_size += owner_sid_size;

	group_sid_size = ndr_size_dom_sid(group, 0);
	if (b_size + group_sid_size < b_size) {
		return -1;
	}
	b_size += group_sid_size;

	if (buflen < b_size) {
		return b_size;
	}

	/* number of hard links */
	PUSH_LE_U32(buf, 0, psbuf->st_ex_nlink);

	/* Reparse tag if FILE_FLAG_REPARSE is set, else zero. */
	PUSH_LE_U32(buf, 4, reparse_tag);

	/*
	 * Remove type info from mode, leaving only the
	 * permissions and setuid/gid bits.
	 */
	PUSH_LE_U32(buf,
		    8,
		    unix_perms_to_wire(psbuf->st_ex_mode & ~S_IFMT));

	buf += 12;
	buflen -= 12;

	/* Now add in the owner and group sids. */
	sid_linearize(buf, buflen, owner);
	buf += owner_sid_size;
	buflen -= owner_sid_size;

	sid_linearize(buf, buflen, group);

	return b_size;
}

/*
 * SMB2 POSIX info level.
 */
ssize_t store_smb2_posix_info(
	connection_struct *conn,
	const SMB_STRUCT_STAT *psbuf,
	uint32_t reparse_tag,
	uint32_t dos_attributes,
	uint8_t *buf,
	size_t buflen)
{
	uint64_t file_id = SMB_VFS_FS_FILE_ID(conn, psbuf);
	struct dom_sid owner = global_sid_NULL;
	struct dom_sid group = global_sid_NULL;
	ssize_t cc_len;

	if (psbuf->st_ex_uid != (uid_t)-1) {
		uid_to_sid(&owner, psbuf->st_ex_uid);
	}
	if (psbuf->st_ex_gid != (gid_t)-1) {
		gid_to_sid(&group, psbuf->st_ex_gid);
	}

	cc_len = smb2_posix_cc_info(
		conn, reparse_tag, psbuf, &owner, &group, NULL, 0);

	if (cc_len == -1) {
		return -1;
	}

	if (cc_len + 68 < 68) {
		return -1;
	}

	if (buflen < cc_len + 68) {
		return cc_len + 68;
	}

	/* Timestamps. */

	/* Birth (creation) time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)buf+0,
			       psbuf->st_ex_btime);
	/* Access time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)buf+8,
			       psbuf->st_ex_atime);
	/* Last write time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)buf+16,
			       psbuf->st_ex_mtime);
	/* Change time. */
	put_long_date_timespec(TIMESTAMP_SET_NT_OR_BETTER,
			       (char *)buf+24,
			       psbuf->st_ex_ctime);

	/* File size 64 Bit */
	SOFF_T(buf,32, get_file_size_stat(psbuf));

	/* Number of bytes used on disk - 64 Bit */
	SOFF_T(buf,40,SMB_VFS_GET_ALLOC_SIZE(conn,NULL,psbuf));

	/* DOS attributes */
	if (S_ISREG(psbuf->st_ex_mode)) {
		PUSH_LE_U32(buf, 48, dos_attributes);
	} else if (S_ISDIR(psbuf->st_ex_mode)) {
		PUSH_LE_U32(buf, 48, dos_attributes|FILE_ATTRIBUTE_DIRECTORY);
	} else {
		/*
		 * All non-directory or regular files are reported
		 * as reparse points. Client may or may not be able
		 * to access these.
		 */
		PUSH_LE_U32(buf, 48, FILE_ATTRIBUTE_REPARSE_POINT);
	}

	/* Add the inode and dev (16 bytes). */
	PUSH_LE_U64(buf, 52, file_id);
	PUSH_LE_U64(buf, 60, psbuf->st_ex_dev);

	/*
	 * Append a POSIX create context (variable bytes).
	 */
	smb2_posix_cc_info(
		conn,
		reparse_tag,
		psbuf,
		&owner,
		&group,
		buf + 68,
		cc_len);

	return cc_len + 68;
}
