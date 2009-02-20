/*
 * Unix SMB/CIFS implementation.
 * Support for OneFS
 *
 * Copyright (C) Steven Danneman, 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ONEFS_H
#define _ONEFS_H

#include "includes.h"
#include "oplock_onefs.h"
#include <sys/isi_acl.h>

/* OneFS Module smb.conf parameters and defaults */

/**
* Specifies when ACLs presented to Windows should be canonicalized
* into the ordering which Explorer expects.
*/
enum onefs_acl_wire_format
{
	ACL_FORMAT_RAW, /**< Never canonicalize */
	ACL_FORMAT_WINDOWS_SD, /**< Only canonicalize synthetic ACLs */
	ACL_FORMAT_ALWAYS /**< Always canonicalize */
};

#define PARM_ONEFS_TYPE "onefs"
#define PARM_ACL_WIRE_FORMAT "acl wire format"
#define PARM_ACL_WIRE_FORMAT_DEFAULT ACL_FORMAT_WINDOWS_SD
#define PARM_ATIME_NOW		"atime now files"
#define PARM_ATIME_NOW_DEFAULT  NULL
#define PARM_ATIME_STATIC	"atime static files"
#define PARM_ATIME_STATIC_DEFAULT NULL
#define PARM_ATIME_SLOP		"atime now slop"
#define PARM_ATIME_SLOP_DEFAULT	 0
#define PARM_CREATOR_OWNER_GETS_FULL_CONTROL "creator owner gets full control"
#define PARM_CREATOR_OWNER_GETS_FULL_CONTROL_DEFAULT true
#define PARM_CTIME_NOW		"ctime now files"
#define PARM_CTIME_NOW_DEFAULT  NULL
#define PARM_CTIME_SLOP		"ctime now slop"
#define PARM_CTIME_SLOP_DEFAULT	0
#define PARM_IGNORE_SACLS "ignore sacls"
#define PARM_IGNORE_SACLS_DEFAULT false
#define PARM_MTIME_NOW		"mtime now files"
#define PARM_MTIME_NOW_DEFAULT	NULL
#define PARM_MTIME_STATIC	"mtime static files"
#define PARM_MTIME_STATIC_DEFAULT NULL
#define PARM_MTIME_SLOP		"mtime now slop"
#define PARM_MTIME_SLOP_DEFAULT	0
#define PARM_USE_READDIRPLUS "use readdirplus"
#define PARM_USE_READDIRPLUS_DEFAULT true
#define PARM_SIMPLE_FILE_SHARING_COMPATIBILITY_MODE "simple file sharing compatibility mode"
#define PARM_SIMPLE_FILE_SHARING_COMPATIBILITY_MODE_DEFAULT false
#define PARM_UNMAPPABLE_SIDS_DENY_EVERYONE "unmappable sids deny everyone"
#define PARM_UNMAPPABLE_SIDS_DENY_EVERYONE_DEFAULT false
#define PARM_UNMAPPABLE_SIDS_IGNORE "ignore unmappable sids"
#define PARM_UNMAPPABLE_SIDS_IGNORE_DEFAULT false
#define PARM_UNMAPPABLE_SIDS_IGNORE_LIST "unmappable sids ignore list"
#define PARM_UNMAPPABLE_SIDS_IGNORE_LIST_DEFAULT NULL

#define IS_CTIME_NOW_PATH(conn,cfg,path)  ((conn) && is_in_path((path),\
	(cfg)->ctime_now_list,(conn)->case_sensitive))
#define IS_MTIME_NOW_PATH(conn,cfg,path)  ((conn) && is_in_path((path),\
	(cfg)->mtime_now_list,(conn)->case_sensitive))
#define IS_ATIME_NOW_PATH(conn,cfg,path)  ((conn) && is_in_path((path),\
	(cfg)->atime_now_list,(conn)->case_sensitive))
#define IS_MTIME_STATIC_PATH(conn,cfg,path)  ((conn) && is_in_path((path),\
	(cfg)->mtime_static_list,(conn)->case_sensitive))
#define IS_ATIME_STATIC_PATH(conn,cfg,path)  ((conn) && is_in_path((path),\
	(cfg)->atime_static_list,(conn)->case_sensitive))

/*
 * Store some commonly evaluated parameters to avoid loadparm pain.
 */

#define ONEFS_VFS_CONFIG_INITIALIZED	0x00010000

#define ONEFS_VFS_CONFIG_FAKETIMESTAMPS	0x00000001

struct onefs_vfs_config
{
	int32 init_flags;

	/* data for fake timestamps */
	int atime_slop;
	int ctime_slop;
	int mtime_slop;

	/* Per-share list of files to fake the create time for. */
        name_compare_entry *ctime_now_list;

	/* Per-share list of files to fake the modification time for. */
	name_compare_entry *mtime_now_list;

	/* Per-share list of files to fake the access time for. */
	name_compare_entry *atime_now_list;

	/* Per-share list of files to fake the modification time for. */
	name_compare_entry *mtime_static_list;

	/* The access  time  will  equal  the  create  time.  */
	/* The  modification  time  will  equal  the  create  time.*/

	/* Per-share list of files to fake the access time for. */
	name_compare_entry *atime_static_list;
};

/*
 * vfs interface handlers
 */
SMB_STRUCT_DIR *onefs_opendir(struct vfs_handle_struct *handle,
			      const char *fname, const char *mask,
			      uint32 attributes);

SMB_STRUCT_DIRENT *onefs_readdir(struct vfs_handle_struct *handle,
				 SMB_STRUCT_DIR *dirp, SMB_STRUCT_STAT *sbuf);

void onefs_seekdir(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp,
		   long offset);

long onefs_telldir(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp);

void onefs_rewinddir(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp);

int onefs_closedir(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dir);

void onefs_init_search_op(struct vfs_handle_struct *handle,
			  SMB_STRUCT_DIR *dirp);

NTSTATUS onefs_create_file(vfs_handle_struct *handle,
			   struct smb_request *req,
			   uint16_t root_dir_fid,
			   const char *fname,
			   uint32_t create_file_flags,
			   uint32_t access_mask,
			   uint32_t share_access,
			   uint32_t create_disposition,
			   uint32_t create_options,
			   uint32_t file_attributes,
			   uint32_t oplock_request,
			   uint64_t allocation_size,
			   struct security_descriptor *sd,
			   struct ea_list *ea_list,
			   files_struct **result,
			   int *pinfo,
			   SMB_STRUCT_STAT *psbuf);

int onefs_close(vfs_handle_struct *handle, struct files_struct *fsp);

int onefs_rename(vfs_handle_struct *handle, const char *oldname,
		 const char *newname);

int onefs_stat(vfs_handle_struct *handle, const char *fname,
	       SMB_STRUCT_STAT *sbuf);

int onefs_fstat(vfs_handle_struct *handle, struct files_struct *fsp,
		SMB_STRUCT_STAT *sbuf);

int onefs_lstat(vfs_handle_struct *handle, const char *path,
		SMB_STRUCT_STAT *sbuf);

int onefs_unlink(vfs_handle_struct *handle, const char *path);

int onefs_chflags(vfs_handle_struct *handle, const char *path,
		  unsigned int flags);

NTSTATUS onefs_streaminfo(vfs_handle_struct *handle,
			  struct files_struct *fsp,
			  const char *fname,
			  TALLOC_CTX *mem_ctx,
			  unsigned int *num_streams,
			  struct stream_struct **streams);

int onefs_vtimes_streams(vfs_handle_struct *handle, const char *fname,
			 int flags, struct timespec times[3]);

NTSTATUS onefs_brl_lock_windows(vfs_handle_struct *handle,
				struct byte_range_lock *br_lck,
				struct lock_struct *plock,
				bool blocking_lock,
				struct blocking_lock_record *blr);

bool onefs_brl_unlock_windows(vfs_handle_struct *handle,
			      struct messaging_context *msg_ctx,
			      struct byte_range_lock *br_lck,
			      const struct lock_struct *plock);

bool onefs_brl_cancel_windows(vfs_handle_struct *handle,
			      struct byte_range_lock *br_lck,
			      struct lock_struct *plock,
			      struct blocking_lock_record *blr);

NTSTATUS onefs_notify_watch(vfs_handle_struct *vfs_handle,
			    struct sys_notify_context *ctx,
			    struct notify_entry *e,
			    void (*callback)(struct sys_notify_context *ctx,
					void *private_data,
					struct notify_event *ev),
			    void *private_data,
			    void *handle_p);

NTSTATUS onefs_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
			   uint32 security_info, SEC_DESC **ppdesc);

NTSTATUS onefs_get_nt_acl(vfs_handle_struct *handle, const char* name,
			  uint32 security_info, SEC_DESC **ppdesc);

NTSTATUS onefs_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
			   uint32 security_info_sent, SEC_DESC *psd);

/*
 * Utility functions
 */
NTSTATUS onefs_samba_sd_to_sd(uint32 security_info_sent, SEC_DESC *psd,
			      struct ifs_security_descriptor *sd, int snum);

NTSTATUS onefs_split_ntfs_stream_name(TALLOC_CTX *mem_ctx, const char *fname,
				      char **pbase, char **pstream);

bool onefs_get_config(int snum, int config_type,
		      struct onefs_vfs_config *cfg);

int onefs_rdp_add_dir_state(connection_struct *conn, SMB_STRUCT_DIR *dirp);

/*
 * System Interfaces
 */
int onefs_sys_create_file(connection_struct *conn,
			  int base_fd,
			  const char *path,
		          uint32_t access_mask,
		          uint32_t open_access_mask,
			  uint32_t share_access,
			  uint32_t create_options,
			  int flags,
			  mode_t mode,
			  int oplock_request,
			  uint64_t id,
			  struct security_descriptor *sd,
			  uint32_t ntfs_flags,
			  int *granted_oplock);

ssize_t onefs_sys_recvfile(int fromfd, int tofd, SMB_OFF_T offset,
			   size_t count);

#endif /* _ONEFS_H */
