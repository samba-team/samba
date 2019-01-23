/*
   Unix SMB/Netbios implementation.
   VFS module to get and set posix acls through xattr
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

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "modules/posixacl_xattr.h"

/*
   POSIX ACL Format:

   Size = 4 (header) + N * 8 (entry)

   Offset  Size    Field (Little Endian)
   -------------------------------------
   0-3     4-byte  Version

   4-5     2-byte  Entry-1 tag
   6-7     2-byte  Entry-1 perm
   8-11    4-byte  Entry-1 id

   12-13   2-byte  Entry-2 tag
   14-15   2-byte  Entry-2 perm
   16-19   4-byte  Entry-2 id

   ...

 */



/* private functions */

#define ACL_EA_ACCESS		"system.posix_acl_access"
#define ACL_EA_DEFAULT		"system.posix_acl_default"
#define ACL_EA_VERSION		0x0002
#define ACL_EA_HEADER_SIZE	4
#define ACL_EA_ENTRY_SIZE	8

#define ACL_EA_SIZE(n)  (ACL_EA_HEADER_SIZE + ((n) * ACL_EA_ENTRY_SIZE))

static SMB_ACL_T mode_to_smb_acl(mode_t mode, TALLOC_CTX *mem_ctx)
{
	struct smb_acl_t *result;
	int count;

	count = 3;
	result = sys_acl_init(mem_ctx);
	if (!result) {
		return NULL;
	}

	result->acl = talloc_array(result, struct smb_acl_entry, count);
	if (!result->acl) {
		errno = ENOMEM;
		talloc_free(result);
		return NULL;
	}

	result->count = count;

	result->acl[0].a_type = SMB_ACL_USER_OBJ;
	result->acl[0].a_perm = (mode & S_IRWXU) >> 6;

	result->acl[1].a_type = SMB_ACL_GROUP_OBJ;
	result->acl[1].a_perm = (mode & S_IRWXG) >> 3;

	result->acl[2].a_type = SMB_ACL_OTHER;
	result->acl[2].a_perm = mode & S_IRWXO;

	return result;
}

static SMB_ACL_T posixacl_xattr_to_smb_acl(const char *buf, size_t xattr_size,
					   TALLOC_CTX *mem_ctx)
{
	int count;
	int size;
	struct smb_acl_entry *smb_ace;
	struct smb_acl_t *result;
	int i;
	int offset;
	uint16_t tag;
	uint16_t perm;
	uint32_t id;

	size = xattr_size;

	if (size < ACL_EA_HEADER_SIZE) {
		/* ACL should be at least as big as the header (4 bytes) */
		errno = EINVAL;
		return NULL;
	}

	/* Version is the first 4 bytes of the ACL */
	if (IVAL(buf, 0) != ACL_EA_VERSION) {
		DEBUG(0, ("Unknown ACL EA version: %d\n",
			  IVAL(buf, 0)));
		errno = EINVAL;
		return NULL;
	}
	offset = ACL_EA_HEADER_SIZE;

	size -= ACL_EA_HEADER_SIZE;
	if (size % ACL_EA_ENTRY_SIZE) {
		/* Size of entries must strictly be a multiple of
		   size of an ACE (8 bytes)
		*/
		DEBUG(0, ("Invalid ACL EA size: %d\n", size));
		errno = EINVAL;
		return NULL;
	}

	count = size / ACL_EA_ENTRY_SIZE;

	result = sys_acl_init(mem_ctx);
	if (!result) {
		return NULL;
	}

	result->acl = talloc_array(result, struct smb_acl_entry, count);
	if (!result->acl) {
		errno = ENOMEM;
		talloc_free(result);
		return NULL;
	}

	result->count = count;

	smb_ace = result->acl;

	for (i = 0; i < count; i++) {
		/* TAG is the first 2 bytes of an entry */
		tag = SVAL(buf, offset);
		offset += 2;

		/* PERM is the next 2 bytes of an entry */
		perm = SVAL(buf, offset);
		offset += 2;

		/* ID is the last 4 bytes of an entry */
		id = IVAL(buf, offset);
		offset += 4;

		switch(tag) {
		case ACL_USER:
			smb_ace->a_type = SMB_ACL_USER;
			break;
		case ACL_USER_OBJ:
			smb_ace->a_type = SMB_ACL_USER_OBJ;
			break;
		case ACL_GROUP:
			smb_ace->a_type = SMB_ACL_GROUP;
			break;
		case ACL_GROUP_OBJ:
			smb_ace->a_type = SMB_ACL_GROUP_OBJ;
			break;
		case ACL_OTHER:
			smb_ace->a_type = SMB_ACL_OTHER;
			break;
		case ACL_MASK:
			smb_ace->a_type = SMB_ACL_MASK;
			break;
		default:
			DEBUG(0, ("unknown tag type %d\n", (unsigned int) tag));
			errno = EINVAL;
			return NULL;
		}


		switch(smb_ace->a_type) {
		case SMB_ACL_USER:
			smb_ace->info.user.uid = id;
			break;
		case SMB_ACL_GROUP:
			smb_ace->info.group.gid = id;
			break;
		default:
			break;
		}

		smb_ace->a_perm = 0;
		smb_ace->a_perm |= ((perm & ACL_READ) ? SMB_ACL_READ : 0);
		smb_ace->a_perm |= ((perm & ACL_WRITE) ? SMB_ACL_WRITE : 0);
		smb_ace->a_perm |= ((perm & ACL_EXECUTE) ? SMB_ACL_EXECUTE : 0);

		smb_ace++;
	}

	return result;
}


static int posixacl_xattr_entry_compare(const void *left, const void *right)
{
	int ret = 0;
	uint16_t tag_left, tag_right;
	uint32_t id_left, id_right;

	/*
	  Sorting precedence:
	   - Smaller TAG values must be earlier.
	   - Within same TAG, smaller identifiers must be earlier, E.g:
	     UID 0 entry must be earlier than UID 200
	     GID 17 entry must be earlier than GID 19
	*/

	/* TAG is the first element in the entry */
	tag_left = SVAL(left, 0);
	tag_right = SVAL(right, 0);

	ret = (tag_left - tag_right);
	if (!ret) {
		/* ID is the third element in the entry, after two short
		   integers (tag and perm), i.e at offset 4.
		*/
		id_left = IVAL(left, 4);
		id_right = IVAL(right, 4);
		ret = id_left - id_right;
	}

	return ret;
}


static int smb_acl_to_posixacl_xattr(SMB_ACL_T theacl, char *buf, size_t len)
{
	ssize_t size;
	struct smb_acl_entry *smb_ace;
	int i;
	int count;
	uint16_t tag;
	uint16_t perm;
	uint32_t id;
	int offset;

	count = theacl->count;

	size = ACL_EA_SIZE(count);
	if (!buf) {
		return size;
	}
	if (len < size) {
		return -ERANGE;
	}
	smb_ace = theacl->acl;

	/* Version is the first 4 bytes of the ACL */
	SIVAL(buf, 0, ACL_EA_VERSION);
	offset = ACL_EA_HEADER_SIZE;

	for (i = 0; i < count; i++) {
		/* Calculate tag */
		switch(smb_ace->a_type) {
		case SMB_ACL_USER:
			tag = ACL_USER;
			break;
		case SMB_ACL_USER_OBJ:
			tag = ACL_USER_OBJ;
			break;
		case SMB_ACL_GROUP:
			tag = ACL_GROUP;
			break;
		case SMB_ACL_GROUP_OBJ:
			tag = ACL_GROUP_OBJ;
			break;
		case SMB_ACL_OTHER:
			tag = ACL_OTHER;
			break;
		case SMB_ACL_MASK:
			tag = ACL_MASK;
			break;
		default:
			DEBUG(0, ("Unknown tag value %d\n",
				  smb_ace->a_type));
			return -EINVAL;
		}


		/* Calculate id */
		switch(smb_ace->a_type) {
		case SMB_ACL_USER:
			id = smb_ace->info.user.uid;
			break;
		case SMB_ACL_GROUP:
			id = smb_ace->info.group.gid;
			break;
		default:
			id = ACL_UNDEFINED_ID;
			break;
		}

		/* Calculate perm */
		perm = 0;
		perm |= (smb_ace->a_perm & SMB_ACL_READ) ? ACL_READ : 0;
		perm |= (smb_ace->a_perm & SMB_ACL_WRITE) ? ACL_WRITE : 0;
		perm |= (smb_ace->a_perm & SMB_ACL_EXECUTE) ? ACL_EXECUTE : 0;

		/* TAG is the first 2 bytes of an entry */
		SSVAL(buf, offset, tag);
		offset += 2;

		/* PERM is the next 2 bytes of an entry */
		SSVAL(buf, offset, perm);
		offset += 2;

		/* ID is the last 4 bytes of an entry */
		SIVAL(buf, offset, id);
		offset += 4;

		smb_ace++;
	}

	/* Skip the header, sort @count number of 8-byte entries */
	qsort(buf+ACL_EA_HEADER_SIZE, count, ACL_EA_ENTRY_SIZE,
	      posixacl_xattr_entry_compare);

	return size;
}

SMB_ACL_T posixacl_xattr_acl_get_file(vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname,
				      SMB_ACL_TYPE_T type,
				      TALLOC_CTX *mem_ctx)
{
	int ret;
	int size;
	char *buf;
	const char *name;

	if (type == SMB_ACL_TYPE_ACCESS) {
		name = ACL_EA_ACCESS;
	} else if (type == SMB_ACL_TYPE_DEFAULT) {
		name = ACL_EA_DEFAULT;
	} else {
		errno = EINVAL;
		return NULL;
	}

	size = ACL_EA_SIZE(20);
	buf = alloca(size);
	if (!buf) {
		return NULL;
	}

	ret = SMB_VFS_GETXATTR(handle->conn, smb_fname,
				name, buf, size);
	if (ret < 0 && errno == ERANGE) {
		size = SMB_VFS_GETXATTR(handle->conn, smb_fname,
					name, NULL, 0);
		if (size > 0) {
			buf = alloca(size);
			if (!buf) {
				return NULL;
			}
			ret = SMB_VFS_GETXATTR(handle->conn,
						smb_fname, name,
						buf, size);
		}
	}

	if (ret > 0) {
		return posixacl_xattr_to_smb_acl(buf, ret, mem_ctx);
	}
	if (ret == 0 || errno == ENOATTR) {
		mode_t mode = 0;
		TALLOC_CTX *frame = talloc_stackframe();
		struct smb_filename *smb_fname_tmp =
			cp_smb_filename_nostream(frame, smb_fname);
		if (smb_fname_tmp == NULL) {
			errno = ENOMEM;
			ret = -1;
		} else {
			ret = SMB_VFS_STAT(handle->conn, smb_fname_tmp);
			if (ret == 0) {
				mode = smb_fname_tmp->st.st_ex_mode;
			}
		}
		TALLOC_FREE(frame);
		if (ret == 0) {
			if (type == SMB_ACL_TYPE_ACCESS) {
				return mode_to_smb_acl(mode, mem_ctx);
			}
			if (S_ISDIR(mode)) {
				return sys_acl_init(mem_ctx);
			}
			errno = EACCES;
		}
	}
	return NULL;
}

SMB_ACL_T posixacl_xattr_acl_get_fd(vfs_handle_struct *handle,
				    files_struct *fsp,
				    TALLOC_CTX *mem_ctx)
{
	int ret;
	int size = ACL_EA_SIZE(20);
	char *buf = alloca(size);

	if (!buf) {
		return NULL;
	}

	ret = SMB_VFS_FGETXATTR(fsp, ACL_EA_ACCESS, buf, size);
	if (ret < 0 && errno == ERANGE) {
		size = SMB_VFS_FGETXATTR(fsp, ACL_EA_ACCESS, NULL, 0);
		if (size > 0) {
			buf = alloca(size);
			if (!buf) {
				return NULL;
			}
			ret = SMB_VFS_FGETXATTR(fsp, ACL_EA_ACCESS, buf, size);
		}
	}

	if (ret > 0) {
		return posixacl_xattr_to_smb_acl(buf, ret, mem_ctx);
	}
	if (ret == 0 || errno == ENOATTR) {
		SMB_STRUCT_STAT sbuf;
		ret = SMB_VFS_FSTAT(fsp, &sbuf);
		if (ret == 0)
			return mode_to_smb_acl(sbuf.st_ex_mode, mem_ctx);
	}
	return NULL;
}

int posixacl_xattr_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T type,
				SMB_ACL_T theacl)
{
	const char *name;
	char *buf;
	ssize_t size;
	int ret;

	size = smb_acl_to_posixacl_xattr(theacl, NULL, 0);
	buf = alloca(size);
	if (!buf) {
		return -1;
	}

	ret = smb_acl_to_posixacl_xattr(theacl, buf, size);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	if (type == SMB_ACL_TYPE_ACCESS) {
		name = ACL_EA_ACCESS;
	} else if (type == SMB_ACL_TYPE_DEFAULT) {
		name = ACL_EA_DEFAULT;
	} else {
		errno = EINVAL;
		return -1;
	}

	return SMB_VFS_SETXATTR(handle->conn, smb_fname,
			name, buf, size, 0);
}

int posixacl_xattr_acl_set_fd(vfs_handle_struct *handle,
			      files_struct *fsp, SMB_ACL_T theacl)
{
	char *buf;
	ssize_t size;
	int ret;

	size = smb_acl_to_posixacl_xattr(theacl, NULL, 0);
	buf = alloca(size);
	if (!buf) {
		return -1;
	}

	ret = smb_acl_to_posixacl_xattr(theacl, buf, size);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	return SMB_VFS_FSETXATTR(fsp, ACL_EA_ACCESS, buf, size, 0);
}

int posixacl_xattr_acl_delete_def_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	return SMB_VFS_REMOVEXATTR(handle->conn,
			smb_fname,
			ACL_EA_DEFAULT);
}
