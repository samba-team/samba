/*
   Unix SMB/CIFS implementation.
   Check access to files based on security descriptors.
   Copyright (C) Jeremy Allison 2005-2006.
   Copyright (C) Michael Adam 2007.

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

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_ACLS

/**
 * Security descriptor / NT Token level access check function.
 */
bool can_access_file_acl(struct connection_struct *conn,
				const char * fname,
				uint32_t access_mask)
{
	NTSTATUS status;
	uint32_t access_granted;
	struct security_descriptor *secdesc = NULL;

	if (conn->server_info->utok.uid == 0 || conn->admin_user) {
		/* I'm sorry sir, I didn't know you were root... */
		return true;
	}

	status = SMB_VFS_GET_NT_ACL(conn, fname,
				    (OWNER_SECURITY_INFORMATION |
				     GROUP_SECURITY_INFORMATION |
				     DACL_SECURITY_INFORMATION),
				    &secdesc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("Could not get acl: %s\n", nt_errstr(status)));
		return false;
	}

	status = se_access_check(secdesc, conn->server_info->ptok,
				 access_mask, &access_granted);
	TALLOC_FREE(secdesc);
	return NT_STATUS_IS_OK(status);
}

/****************************************************************************
 Actually emulate the in-kernel access checking for delete access. We need
 this to successfully return ACCESS_DENIED on a file open for delete access.
****************************************************************************/

bool can_delete_file_in_directory(connection_struct *conn, const char *fname)
{
	SMB_STRUCT_STAT sbuf;
	TALLOC_CTX *ctx = talloc_tos();
	char *dname = NULL;

	if (!CAN_WRITE(conn)) {
		return False;
	}

	/* Get the parent directory permission mask and owners. */
	if (!parent_dirname(ctx, fname, &dname, NULL)) {
		return False;
	}
	if(SMB_VFS_STAT(conn, dname, &sbuf) != 0) {
		return False;
	}

	/* fast paths first */

	if (!S_ISDIR(sbuf.st_mode)) {
		return False;
	}
	if (conn->server_info->utok.uid == 0 || conn->admin_user) {
		/* I'm sorry sir, I didn't know you were root... */
		return True;
	}

#ifdef S_ISVTX
	/* sticky bit means delete only by owner or root. */
	if (sbuf.st_mode & S_ISVTX) {
		SMB_STRUCT_STAT sbuf_file;
		if(SMB_VFS_STAT(conn, fname, &sbuf_file) != 0) {
			if (errno == ENOENT) {
				/* If the file doesn't already exist then
				 * yes we'll be able to delete it. */
				return True;
			}
			return False;
		}
		/*
		 * Patch from SATOH Fumiyasu <fumiyas@miraclelinux.com>
		 * for bug #3348. Don't assume owning sticky bit
		 * directory means write access allowed.
		 */
		if (conn->server_info->utok.uid != sbuf_file.st_uid) {
			return False;
		}
	}
#endif

	/* now for ACL checks */

	/*
	 * There's two ways to get the permission to delete a file: First by
	 * having the DELETE bit on the file itself and second if that does
	 * not help, by the DELETE_CHILD bit on the containing directory.
	 *
	 * Here we only check the directory permissions, we will
	 * check the file DELETE permission separately.
	 */

	return can_access_file_acl(conn, dname, FILE_DELETE_CHILD);
}

/****************************************************************************
 Actually emulate the in-kernel access checking for read/write access. We need
 this to successfully check for ability to write for dos filetimes.
 Note this doesn't take into account share write permissions.
****************************************************************************/

bool can_access_file_data(connection_struct *conn, const char *fname, SMB_STRUCT_STAT *psbuf, uint32 access_mask)
{
	if (!(access_mask & (FILE_READ_DATA|FILE_WRITE_DATA))) {
		return False;
	}
	access_mask &= (FILE_READ_DATA|FILE_WRITE_DATA);

	/* some fast paths first */

	DEBUG(10,("can_access_file_data: requesting 0x%x on file %s\n",
		(unsigned int)access_mask, fname ));

	if (conn->server_info->utok.uid == 0 || conn->admin_user) {
		/* I'm sorry sir, I didn't know you were root... */
		return True;
	}

	if (!VALID_STAT(*psbuf)) {
		/* Get the file permission mask and owners. */
		if(SMB_VFS_STAT(conn, fname, psbuf) != 0) {
			return False;
		}
	}

	/* Check primary owner access. */
	if (conn->server_info->utok.uid == psbuf->st_uid) {
		switch (access_mask) {
			case FILE_READ_DATA:
				return (psbuf->st_mode & S_IRUSR) ? True : False;

			case FILE_WRITE_DATA:
				return (psbuf->st_mode & S_IWUSR) ? True : False;

			default: /* FILE_READ_DATA|FILE_WRITE_DATA */

				if ((psbuf->st_mode & (S_IWUSR|S_IRUSR)) == (S_IWUSR|S_IRUSR)) {
					return True;
				} else {
					return False;
				}
		}
	}

	/* now for ACL checks */

	return can_access_file_acl(conn, fname, access_mask);
}

/****************************************************************************
 Userspace check for write access.
 Note this doesn't take into account share write permissions.
****************************************************************************/

bool can_write_to_file(connection_struct *conn, const char *fname, SMB_STRUCT_STAT *psbuf)
{
	return can_access_file_data(conn, fname, psbuf, FILE_WRITE_DATA);
}

/****************************************************************************
 Check for an existing default Windows ACL on a directory.
****************************************************************************/

bool directory_has_default_acl(connection_struct *conn, const char *fname)
{
	/* returns talloced off tos. */
	struct security_descriptor *secdesc = NULL;
	unsigned int i;
	NTSTATUS status = SMB_VFS_GET_NT_ACL(conn, fname,
				DACL_SECURITY_INFORMATION, &secdesc);

	if (!NT_STATUS_IS_OK(status) || secdesc == NULL) {
		return false;
	}

	for (i = 0; i < secdesc->dacl->num_aces; i++) {
		struct security_ace *psa = &secdesc->dacl->aces[i];
		if (psa->flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
				SEC_ACE_FLAG_CONTAINER_INHERIT)) {
			TALLOC_FREE(secdesc);
			return true;
		}
	}
	TALLOC_FREE(secdesc);
	return false;
}
