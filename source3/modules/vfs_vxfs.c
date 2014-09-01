/*
Unix SMB/CIFS implementation.
Wrap VxFS calls in vfs functions.
This module is for ACL handling.

Copyright (C) Symantec Corporation <www.symantec.com> 2014

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
#include "librpc/gen_ndr/ndr_xattr.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "system/filesys.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define MODULE_NAME "vxfs"

/*
 * WARNING !! WARNING !!
 *
 * DO NOT CHANGE THIS FROM "system." space to
 * "user." space unless you are shipping a product
 * that RESTRICTS access to extended attributes
 * to smbd-only. "system." space is restricted
 * to root access only, "user." space is available
 * to ANY USER.
 *
 * If this is changed to "user." and access
 * to extended attributes is available via
 * local processes or other remote file system
 * (e.g. NFS) then the security of the system
 * WILL BE COMPROMISED. i.e. non-root users
 * WILL be able to overwrite Samba ACLs on
 * the file system.
 *
 * If you need to modify this define, do
 * so using CFLAGS on your build command
 * line.
 * e.g. CFLAGS=-DXATTR_USER_NTACL="user.NTACL"
 *
 * Added by: <jra@samba.org> 17 Sept. 2014.
 *
 */

#ifndef XATTR_USER_NTACL
#define XATTR_USER_NTACL "system.NTACL"
#endif

/* type values */
#define VXFS_ACL_UNDEFINED_TYPE  0
#define VXFS_ACL_USER_OBJ        1
#define VXFS_ACL_GROUP_OBJ       2
#define VXFS_ACL_USER            3
#define VXFS_ACL_GROUP           4
#define VXFS_ACL_OTHER           5
#define VXFS_ACL_MASK            6


/*
 * Compare aces
 * This will compare two ace entries for sorting
 * each entry contains: type, perms and id
 * Sort by type first, if type is same sort by id.
 */
static int vxfs_ace_cmp(const void *ace1, const void *ace2)
{
	int ret = 0;
	uint16_t type_a1, type_a2;
	uint32_t id_a1, id_a2;

	/* Type must be compared first */
	type_a1 = SVAL(ace1, 0);
	type_a2 = SVAL(ace2, 0);

	ret = (type_a1 - type_a2);
	if (!ret) {
		/* Compare ID under type */
		/* skip perm thus take offset as 4*/
		id_a1 = IVAL(ace1, 4);
		id_a2 = IVAL(ace2, 4);
		ret = id_a1 - id_a2;
	}

	return ret;
}

static void vxfs_print_ace_buf(char *buf, int count) {

	int i, offset = 0;
	uint16_t type, perm;
	uint32_t id;

	DEBUG(10, ("vfs_vxfs: Printing aces:\n"));
	for (i = 0; i < count; i++) {
		type = SVAL(buf, offset);
		offset += 2;
		perm = SVAL(buf, offset);
		offset += 2;
		id = IVAL(buf, offset);
		offset += 4;

		DEBUG(10, ("vfs_vxfs: type = %u, perm = %u, id = %u\n",
			  (unsigned int)type, (unsigned int)perm,
			  (unsigned int)id));
	}
}

/*
 * Sort aces so that comparing 2 ACLs will be straight forward.
 * This function will fill buffer as follows:
 * For each ace:
 * 	1. ace->a_type will be filled as first 2 bytes in buf.
 * 	2. ace->a_perm will be filled as next 2 bytes.
 * 	3. ace->xid will be filled as next 4 bytes.
 * Thus each ace entry in buf is equal to 8 bytes.
 * Also a_type is mapped to VXFS_ACL_* so that ordering aces
 * becomes easy.
 */
static char * vxfs_sort_acl(SMB_ACL_T theacl, TALLOC_CTX *mem_ctx,
			    uint32_t o_uid,
			    uint32_t o_gid) {

	struct smb_acl_entry *smb_ace;
	int i, count;
	uint16_t type, perm;
	uint32_t id;
	int offset = 0;
	char *buf = NULL;

	count = theacl->count;

	buf = talloc_zero_size(mem_ctx, count * 8);
	if (!buf) {
		return NULL;
	}

	smb_ace = theacl->acl;

	for (i = 0; i < count; i++) {
		/* Calculate type */
		/* Map type to SMB_ACL_* to VXFS_ACL_* */
		switch(smb_ace->a_type) {
		case SMB_ACL_USER:
			type = VXFS_ACL_USER;
			break;
		case SMB_ACL_USER_OBJ:
			type = VXFS_ACL_USER_OBJ;
			break;
		case SMB_ACL_GROUP:
			type = VXFS_ACL_GROUP;
			break;
		case SMB_ACL_GROUP_OBJ:
			type = VXFS_ACL_GROUP_OBJ;
			break;
		case SMB_ACL_OTHER:
			type = VXFS_ACL_OTHER;
			break;
		case SMB_ACL_MASK:
			type = VXFS_ACL_MASK;
			break;
		default:
			type = -1;
			talloc_free(buf);
			return NULL;
		}

		type = type & 0xff;

		/* Calculate id:
		 * We get owner uid and owner group gid in o_uid and o_gid
		 * Put these ids instead of -1
		 */
		switch(smb_ace->a_type) {
		case SMB_ACL_USER:
			id = smb_ace->info.user.uid;
			break;
		case SMB_ACL_GROUP:
			id = smb_ace->info.group.gid;
			break;
		case SMB_ACL_USER_OBJ:
			id = o_uid;
			break;
		case SMB_ACL_GROUP_OBJ:
			id = o_gid;
			break;
		case SMB_ACL_MASK:
		case SMB_ACL_OTHER:
			id = -1;
			break;
		default:
			/* Can't happen.. */
			id = -1;
			break;
		}

		/* Calculate perm */
		perm = smb_ace->a_perm & 0xff;

		/* TYPE is the first 2 bytes of an entry */
		SSVAL(buf, offset, type);
		offset += 2;

		/* PERM is the next 2 bytes of an entry */
		SSVAL(buf, offset, perm);
		offset += 2;

		/* ID is the last 4 bytes of an entry */
		SIVAL(buf, offset, id);
		offset += 4;

		smb_ace++;
	}

	qsort(buf, count, 8, vxfs_ace_cmp);

	DEBUG(10, ("vfs_vxfs: Print sorted aces:\n"));
	vxfs_print_ace_buf(buf, count);

	return buf;
}

/* This function gets e_buf as an arg which is sorted and created out of
 * existing ACL. This function will compact this e_buf to c_buf where USER
 * and GROUP aces matching with USER_OBJ and GROUP_OBJ will be merged
 * respectively.
 * This is similar to what posix_acls.c does. This will make sure existing
 * acls are converted much similar to what posix_acls calculates.
 */

static char * vxfs_compact_buf(char *e_buf, int *new_count, int count,
			       TALLOC_CTX *mem_ctx)
{
	int i, e_offset = 0, c_offset = 0;
	uint16_t type, perm, o_perm;
	uint32_t id, owner_id, group_id;
	char *c_buf = NULL;


	if (count < 2) {
		return NULL;
	}

	c_buf = talloc_zero_size(mem_ctx, count * 8);
	if (!c_buf) {
		return NULL;
	}

	/*Copy first two enries from e_buf to c_buf
	 *These are USER_OBJ and GROUP_OBJ
	 */

	memcpy(c_buf, e_buf, 16);

	(*new_count) = 2;

	owner_id = IVAL(e_buf, 4);
	group_id = IVAL(e_buf, 12);

	c_offset = e_offset = 16;

	/* Start comparing other entries */
	for (i = 2; i < count; i++) {

		type = SVAL(e_buf, e_offset);
		e_offset += 2;
		perm = SVAL(e_buf, e_offset);
		e_offset += 2;
		id = IVAL(e_buf, e_offset);
		e_offset += 4;

		switch(type) {
		case VXFS_ACL_USER:
			if (id == owner_id) {
				o_perm = SVAL(c_buf, 2);
				o_perm |= perm;
				SSVAL(c_buf, 2, o_perm);
				DEBUG(10, ("vfs_vxfs: merging with owner"
					  "e_type = %u,"
					  "e_perm = %u,"
					  "e_id = %u\n", (unsigned int)type,
					  (unsigned int)perm,
					  (unsigned int)id));
				continue;
			}
			break;
		case VXFS_ACL_GROUP:
			if (id == group_id) {
				o_perm = SVAL(c_buf, 10);
				o_perm |= perm;
				SSVAL(c_buf, 10, o_perm);
				DEBUG(10, ("vfs_vxfs: merging with owner group"
					  "e_type = %u,"
					  "e_perm = %u,"
					  "e_id = %u\n", (unsigned int)type,
					  (unsigned int)perm,
					  (unsigned int)id));
				continue;
			}
			break;
		}

		SSVAL(c_buf, c_offset, type);
		c_offset += 2;

		SSVAL(c_buf, c_offset, perm);
		c_offset += 2;

		SIVAL(c_buf, c_offset, id);
		c_offset += 4;

		(*new_count)++;
	}
	DEBUG(10, ("vfs_vxfs: new_count is %d\n", *new_count));
	return c_buf;
}

/* Actually compare New ACL and existing ACL buf */
static bool vxfs_compare_acls(char *e_buf, char *n_buf, int n_count,
			      int e_count) {

	uint16_t e_type, n_type, e_perm, n_perm;
	uint32_t e_id, n_id;
	int i, offset = 0;

	if (!e_buf && !n_buf) {
		DEBUG(10, ("vfs_vxfs: Empty buffers!\n"));
		return false;
	}

	if ((e_count < 2) || (n_count < 2)) {
		return false;
	}
	/*Get type from last entry from both buffers.
	 * It may or may not be ACL_MASK
	 */
	n_type = SVAL(n_buf, offset + (8 * (n_count-1)));
	e_type = SVAL(e_buf, offset + (8 * (e_count-1)));

	/* Check for ACL_MASK entry properly. Handle all 4 cases*/

	/* If ACL_MASK entry is present in any of the buffers,
	 * it will be always the last one. Calculate count to compare
	 * based on if ACL_MASK is present on new and existing ACL
	 */
	if ((n_type != VXFS_ACL_MASK) && (e_type == VXFS_ACL_MASK)){
		DEBUG(10, ("vfs_vxfs: New ACL does not have mask entry,"
			   "reduce count by 1 and compare\n"));
		e_count = e_count -1;
	}
	if ((n_type == VXFS_ACL_MASK) && (e_type != VXFS_ACL_MASK)){
		DEBUG(10, ("vfs_vxfs: new ACL to be set contains mask"
			   "existing ACL does not have mask entry\n"
			   "Need to set New ACL\n"));
		return false;
	}

	if (memcmp(e_buf, n_buf, (e_count * 8)) != 0) {
		DEBUG(10, ("vfs_vxfs: Compare with memcmp,"
			   "buffers not same!\n"));
		return false;
	}

	return true;
}

/* In VxFS, POSIX ACLs are pointed by separate inode for each file/dir.
 * However, files/dir share same POSIX ACL inode if ACLs are inherited
 * from parent.
 * To retain this behaviour, below function avoids ACL set call if
 * underlying ACLs are already same and thus saves creating extra inode.
 *
 * This function will execute following steps:
 * 1. Get existing ACL
 * 2. Sort New ACL and existing ACL into buffers
 * 3. Compact existing ACL buf
 * 4. Finally compare New ACL buf and Compact buf
 * 5. If same, return true
 * 6. Else need to set New ACL
 */

static bool vxfs_compare(connection_struct *conn, char *name, SMB_ACL_T the_acl,
			 SMB_ACL_TYPE_T the_acl_type)
{
	SMB_ACL_T existing_acl = NULL;
	bool ret = false;
	int i, count = 0;
	TALLOC_CTX *mem_ctx = talloc_tos();
	char *existing_buf = NULL, *new_buf = NULL, *compact_buf = NULL;
	struct smb_filename *smb_fname = NULL;
	int status;

	DEBUG(10, ("vfs_vxfs: Getting existing ACL for %s\n", name));
	existing_acl = SMB_VFS_SYS_ACL_GET_FILE(conn, name, the_acl_type,
						mem_ctx);
	if (existing_acl == NULL) {
		DEBUG(10, ("vfs_vxfs: Failed to get ACL\n"));
		goto out;
	}

	DEBUG(10, ("vfs_vxfs: Existing ACL count=%d\n", existing_acl->count));
	DEBUG(10, ("vfs_vxfs: New ACL count=%d\n", the_acl->count));

	if (existing_acl->count == 0) {
		DEBUG(10, ("vfs_vxfs: ACL count is 0, Need to set\n"));
		goto out;
	}

	smb_fname = synthetic_smb_fname(mem_ctx, name, NULL, NULL);
	if (smb_fname == NULL) {
		DEBUG(10, ("vfs_vxfs: Failed to create smb_fname\n"));
		goto out;
	}

	status = SMB_VFS_STAT(conn, smb_fname);
	if (status == -1) {
		DEBUG(10, ("vfs_vxfs: stat failed!\n"));
		goto out;
	}

	DEBUG(10, ("vfs_vxfs: Sorting existing ACL\n"));
	existing_buf = vxfs_sort_acl(existing_acl, mem_ctx,
				     smb_fname->st.st_ex_uid,
				     smb_fname->st.st_ex_gid);
	if (!existing_buf)
		goto out;

	DEBUG(10, ("vfs_vxfs: Sorting new ACL\n"));
	new_buf = vxfs_sort_acl(the_acl, mem_ctx, smb_fname->st.st_ex_uid,
				smb_fname->st.st_ex_gid);
	if (!new_buf) {
		goto out;
	}

	DEBUG(10, ("vfs_vxfs: Compact existing buf\n"));
	compact_buf = vxfs_compact_buf(existing_buf, &count,
				       existing_acl->count,
				       mem_ctx);
	if (!compact_buf) {
		goto out;
	}

	vxfs_print_ace_buf(compact_buf, count);

	/* COmpare ACLs only if count is same or mismatch by 1 */
	if ((count == the_acl->count) ||
	   (count == the_acl->count + 1) ||
	   (count+1 == the_acl->count)) {

		if (vxfs_compare_acls(compact_buf, new_buf, the_acl->count,
				     count)) {
			DEBUG(10, ("vfs_vxfs: ACLs matched. Not setting.\n"));
			ret = true;
			goto out;
		} else
			DEBUG(10, ("vfs_vxfs: ACLs NOT matched. Setting\n"));
	} else {
		DEBUG(10, ("vfs_vxfs: ACLs count does not match. Setting\n"));
	}

out:

	TALLOC_FREE(existing_acl);
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(existing_buf);
	TALLOC_FREE(compact_buf);
	TALLOC_FREE(new_buf);

	return ret;
}

static int vxfs_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_ACL_T theacl)
{

	if (vxfs_compare(fsp->conn, fsp->fsp_name->base_name, theacl,
			 SMB_ACL_TYPE_ACCESS)) {
		return 0;
	}

	return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);
}

static int vxfs_sys_acl_set_file(vfs_handle_struct *handle,  const char *name,
				 SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	if (vxfs_compare(handle->conn, (char *)name, theacl, acltype)) {
		return 0;
	}

	return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, name, acltype, theacl);
}

static int vxfs_set_xattr(struct vfs_handle_struct *handle,  const char *path,
			  const char *name, const void *value, size_t size,
			  int flags){

	DEBUG(10, ("In vxfs_set_xattr\n"));

	if (strcmp(name, XATTR_NTACL_NAME) == 0) {
		return SMB_VFS_NEXT_SETXATTR(handle, path, XATTR_USER_NTACL,
					     value, size, flags);
	}

	/* Clients can't set XATTR_USER_NTACL directly. */
	if (strcasecmp(name, XATTR_USER_NTACL) == 0) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_SETXATTR(handle, path, name, value, size, flags);
}

static int vxfs_fset_xattr(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, const char *name,
			   const void *value, size_t size,  int flags){

	DEBUG(10, ("In vxfs_fset_xattr\n"));

	if (strcmp(name, XATTR_NTACL_NAME) == 0) {
		return SMB_VFS_NEXT_FSETXATTR(handle, fsp, XATTR_USER_NTACL,
					      value, size, flags);
	}

	/* Clients can't set XATTR_USER_NTACL directly. */
	if (strcasecmp(name, XATTR_USER_NTACL) == 0) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);
}

static ssize_t vxfs_get_xattr(struct vfs_handle_struct *handle,
			      const char *path, const char *name,
			      void *value, size_t size){

	DEBUG(10, ("In vxfs_get_xattr\n"));

	if (strcmp(name, XATTR_NTACL_NAME) == 0) {
		return SMB_VFS_NEXT_GETXATTR(handle, path, XATTR_USER_NTACL,
					     value, size);
	}

	/* Clients can't see XATTR_USER_NTACL directly. */
	if (strcasecmp(name, XATTR_USER_NTACL) == 0) {
		errno = ENOATTR;
		return -1;
	}

	return SMB_VFS_NEXT_GETXATTR(handle, path, name, value, size);
}

static ssize_t vxfs_fget_xattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, const char *name,
			       void *value, size_t size){

	DEBUG(10, ("In vxfs_fget_xattr\n"));

	if (strcmp(name, XATTR_NTACL_NAME) == 0) {
		return SMB_VFS_NEXT_FGETXATTR(handle, fsp, XATTR_USER_NTACL,
					      value, size);
	}

	/* Clients can't see XATTR_USER_NTACL directly. */
	if (strcasecmp(name, XATTR_USER_NTACL) == 0) {
		errno = ENOATTR;
		return -1;
	}

	return SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
}

static int vxfs_remove_xattr(struct vfs_handle_struct *handle,
			     const char *path, const char *name){

	DEBUG(10, ("In vxfs_remove_xattr\n"));

	if (strcmp(name, XATTR_NTACL_NAME) == 0) {
		return SMB_VFS_NEXT_REMOVEXATTR(handle, path, XATTR_USER_NTACL);
	}

	/* Clients can't see XATTR_USER_NTACL directly. */
	if (strcasecmp(name, XATTR_USER_NTACL) == 0) {
		errno = ENOATTR;
		return -1;
	}

	return SMB_VFS_NEXT_REMOVEXATTR(handle, path, name);
}

static int vxfs_fremove_xattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name){

	DEBUG(10, ("In vxfs_fremove_xattr\n"));

	if (strcmp(name, XATTR_NTACL_NAME) == 0) {
		return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, XATTR_USER_NTACL);
	}

	/* Clients can't remove XATTR_USER_NTACL directly. */
	if (strcasecmp(name, XATTR_USER_NTACL) == 0) {
		errno = ENOATTR;
		return -1;
	}

	return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static size_t vxfs_filter_list(char *list, size_t size)
{
	char *str = list;

	while (str - list < size) {
		size_t element_len = strlen(str) + 1;
		if (strcasecmp(str, XATTR_USER_NTACL) == 0) {
			memmove(str,
				str + element_len,
				size - (str - list) - element_len);
			size -= element_len;
			continue;
		}
		str += element_len;
	}
	return size;
}

static ssize_t vxfs_listxattr(vfs_handle_struct *handle, const char *path,
                              char *list, size_t size)
{
	ssize_t result;

	result = SMB_VFS_NEXT_LISTXATTR(handle, path, list, size);

	if (result <= 0) {
		return result;
	}

	/* Remove any XATTR_USER_NTACL elements from the returned list. */
	result = vxfs_filter_list(list, result);

        return result;
}

static ssize_t vxfs_flistxattr(struct vfs_handle_struct *handle,
                                struct files_struct *fsp, char *list,
                                size_t size)
{
	ssize_t result;

	result = SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);

	if (result <= 0) {
		return result;
	}

	/* Remove any XATTR_USER_NTACL elements from the returned list. */
	result = vxfs_filter_list(list, result);

        return result;
}

static int vfs_vxfs_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{

	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}
	return 0;
}

static struct vfs_fn_pointers vfs_vxfs_fns = {
	.connect_fn = vfs_vxfs_connect,

	.sys_acl_set_file_fn = vxfs_sys_acl_set_file,
	.sys_acl_set_fd_fn = vxfs_sys_acl_set_fd,

	.getxattr_fn = vxfs_get_xattr,
	.fgetxattr_fn = vxfs_fget_xattr,
	.listxattr_fn = vxfs_listxattr,
	.flistxattr_fn = vxfs_flistxattr,
	.removexattr_fn = vxfs_remove_xattr,
	.fremovexattr_fn = vxfs_fremove_xattr,
	.setxattr_fn = vxfs_set_xattr,
	.fsetxattr_fn = vxfs_fset_xattr,
};

NTSTATUS vfs_vxfs_init(void);
NTSTATUS vfs_vxfs_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "vxfs",
				&vfs_vxfs_fns);
}
