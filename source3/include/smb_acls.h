/* 
   Unix SMB/CIFS implementation.
   Portable SMB ACL interface
   Copyright (C) Jeremy Allison 2000
   
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

#ifndef _SMB_ACLS_H
#define _SMB_ACLS_H

#include "librpc/gen_ndr/smb_acl.h"

struct vfs_handle_struct;
struct files_struct;
struct smb_filename;

typedef int			SMB_ACL_TYPE_T;
/*
 * struct smb_acl_entry is defined in IDL as
 * using mode_t values, pidl always converts these
 * to uint32_t. Ensure the external type definitions
 * match.
 */
typedef uint32_t		*SMB_ACL_PERMSET_T;
typedef uint32_t		SMB_ACL_PERM_T;

typedef enum smb_acl_tag_t SMB_ACL_TAG_T;
typedef struct smb_acl_t *SMB_ACL_T;

typedef struct smb_acl_entry 	*SMB_ACL_ENTRY_T;

/* The following definitions come from lib/sysacls.c  */

int sys_acl_get_entry(SMB_ACL_T acl_d, int entry_id, SMB_ACL_ENTRY_T *entry_p);
int sys_acl_get_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *type_p);
int sys_acl_get_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p);
void *sys_acl_get_qualifier(SMB_ACL_ENTRY_T entry_d);
int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset_d);
int sys_acl_add_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm);
int sys_acl_get_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm);
char *sys_acl_to_text(const struct smb_acl_t *acl_d, ssize_t *len_p);
SMB_ACL_T sys_acl_init(TALLOC_CTX *mem_ctx);
int sys_acl_create_entry(SMB_ACL_T *acl_p, SMB_ACL_ENTRY_T *entry_p);
int sys_acl_set_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T tag_type);
int sys_acl_set_qualifier(SMB_ACL_ENTRY_T entry_d, void *qual_p);
int sys_acl_set_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T permset_d);
int sys_acl_free_text(char *text);
int sys_acl_valid(SMB_ACL_T acl_d);
SMB_ACL_T sys_acl_get_file(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			SMB_ACL_TYPE_T type,
			TALLOC_CTX *mem_ctx);
SMB_ACL_T sys_acl_get_fd(struct vfs_handle_struct *handle, struct files_struct *fsp,
			 TALLOC_CTX *mem_ctx);
int sys_acl_set_file(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			SMB_ACL_TYPE_T type,
			SMB_ACL_T acl_d);
int sys_acl_set_fd(struct vfs_handle_struct *handle, struct files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname);
int no_acl_syscall_error(int err);

#endif /* _SMB_ACLS_H */
