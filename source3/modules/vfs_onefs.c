/*
 * Unix SMB/CIFS implementation.
 * Support for OneFS
 *
 * Copyright (C) Tim Prouty, 2008
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

#include "includes.h"
#include "onefs.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define ONEFS_DATA_FASTBUF	10

struct onefs_vfs_config share_config[ONEFS_DATA_FASTBUF];
struct onefs_vfs_config *pshare_config;

static void onefs_load_faketimestamp_config(struct vfs_handle_struct *handle,
					    struct onefs_vfs_config *cfg)
{
	const char **parm;
	int snum = SNUM(handle->conn);

	parm = lp_parm_string_list(snum, PARM_ONEFS_TYPE, PARM_ATIME_NOW,
				   PARM_ATIME_NOW_DEFAULT);

	if (parm) {
		cfg->init_flags |= ONEFS_VFS_CONFIG_FAKETIMESTAMPS;
		set_namearray(&cfg->atime_now_list,*parm);
	}

	parm = lp_parm_string_list(snum, PARM_ONEFS_TYPE, PARM_CTIME_NOW,
				   PARM_CTIME_NOW_DEFAULT);

	if (parm) {
		cfg->init_flags |= ONEFS_VFS_CONFIG_FAKETIMESTAMPS;
		set_namearray(&cfg->ctime_now_list,*parm);
	}

	parm = lp_parm_string_list(snum, PARM_ONEFS_TYPE, PARM_MTIME_NOW,
				   PARM_MTIME_NOW_DEFAULT);

	if (parm) {
		cfg->init_flags |= ONEFS_VFS_CONFIG_FAKETIMESTAMPS;
		set_namearray(&cfg->mtime_now_list,*parm);
	}

	parm = lp_parm_string_list(snum, PARM_ONEFS_TYPE, PARM_ATIME_STATIC,
				   PARM_ATIME_STATIC_DEFAULT);

	if (parm) {
		cfg->init_flags |= ONEFS_VFS_CONFIG_FAKETIMESTAMPS;
		set_namearray(&cfg->atime_static_list,*parm);
	}

	parm = lp_parm_string_list(snum, PARM_ONEFS_TYPE, PARM_MTIME_STATIC,
				   PARM_MTIME_STATIC_DEFAULT);

	if (parm) {
		cfg->init_flags |= ONEFS_VFS_CONFIG_FAKETIMESTAMPS;
		set_namearray(&cfg->mtime_static_list,*parm);
	}

	cfg->atime_slop = lp_parm_int(snum, PARM_ONEFS_TYPE, PARM_ATIME_SLOP,
				      PARM_ATIME_SLOP_DEFAULT);
	cfg->ctime_slop = lp_parm_int(snum, PARM_ONEFS_TYPE, PARM_CTIME_SLOP,
				      PARM_CTIME_SLOP_DEFAULT);
	cfg->mtime_slop = lp_parm_int(snum, PARM_ONEFS_TYPE, PARM_MTIME_SLOP,
				      PARM_MTIME_SLOP_DEFAULT);
}


static int onefs_load_config(struct vfs_handle_struct *handle)
{
	int snum = SNUM(handle->conn);
	int share_count = lp_numservices();

	if (!pshare_config) {

		if (share_count <= ONEFS_DATA_FASTBUF)
			pshare_config = share_config;
		else {
			pshare_config =
			    SMB_MALLOC_ARRAY(struct onefs_vfs_config,
					     share_count);
			if (!pshare_config) {
				errno = ENOMEM;
				return -1;
			}

			memset(pshare_config, 0,
			    (sizeof(struct onefs_vfs_config) * share_count));
		}
	}

	if ((pshare_config[snum].init_flags &
		ONEFS_VFS_CONFIG_INITIALIZED) == 0) {
			pshare_config[snum].init_flags =
			    ONEFS_VFS_CONFIG_INITIALIZED;
			onefs_load_faketimestamp_config(handle,
						        &pshare_config[snum]);
	}

	return 0;
}

bool onefs_get_config(int snum, int config_type,
		      struct onefs_vfs_config *cfg)
{
	if (share_config[snum].init_flags & config_type)
		*cfg = share_config[snum];
	else
		return false;

	return true;
}

static int onefs_connect(struct vfs_handle_struct *handle, const char *service,
			 const char *user)
{
	int ret = onefs_load_config(handle);

	if (ret)
		return ret;

	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static int onefs_mkdir(vfs_handle_struct *handle, const char *path,
		       mode_t mode)
{
	/* SMB_VFS_MKDIR should never be called in vfs_onefs */
	SMB_ASSERT(false);
	return SMB_VFS_NEXT_MKDIR(handle, path, mode);
}

static int onefs_open(vfs_handle_struct *handle, const char *fname,
		      files_struct *fsp, int flags, mode_t mode)
{
	/* SMB_VFS_OPEN should never be called in vfs_onefs */
	SMB_ASSERT(false);
	return SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);
}

static ssize_t onefs_recvfile(vfs_handle_struct *handle, int fromfd,
			      files_struct *tofsp, SMB_OFF_T offset,
			      size_t count)
{
	ssize_t result;

	START_PROFILE_BYTES(syscall_recvfile, count);
	result = onefs_sys_recvfile(fromfd, tofsp->fh->fd, offset, count);
	END_PROFILE(syscall_recvfile);
	return result;
}

static uint64_t onefs_get_alloc_size(struct vfs_handle_struct *handle,
				     files_struct *fsp,
				     const SMB_STRUCT_STAT *sbuf)
{
	uint64_t result;

	START_PROFILE(syscall_get_alloc_size);

	if(S_ISDIR(sbuf->st_mode)) {
		result = 0;
		goto out;
	}

	/* Just use the file size since st_blocks is unreliable on OneFS. */
	result = get_file_size_stat(sbuf);

	if (fsp && fsp->initial_allocation_size)
		result = MAX(result,fsp->initial_allocation_size);

	result = smb_roundup(handle->conn, result);

 out:
	END_PROFILE(syscall_get_alloc_size);
	return result;
}

static int onefs_statvfs(vfs_handle_struct *handle, const char *path,
			 vfs_statvfs_struct *statbuf)
{
	struct statvfs statvfs_buf;
	int result;

	DEBUG(5, ("Calling SMB_STAT_VFS \n"));
	result = statvfs(path, &statvfs_buf);
	ZERO_STRUCTP(statbuf);

	if (!result) {
		statbuf->OptimalTransferSize = statvfs_buf.f_iosize;
		statbuf->BlockSize = statvfs_buf.f_bsize;
		statbuf->TotalBlocks = statvfs_buf.f_blocks;
		statbuf->BlocksAvail = statvfs_buf.f_bfree;
		statbuf->UserBlocksAvail = statvfs_buf.f_bavail;
		statbuf->TotalFileNodes = statvfs_buf.f_files;
		statbuf->FreeFileNodes = statvfs_buf.f_ffree;
		statbuf->FsIdentifier =
		    (((uint64_t)statvfs_buf.f_fsid.val[0]<<32) &
			0xffffffff00000000LL) |
		    (uint64_t)statvfs_buf.f_fsid.val[1];
	}
        return result;
}

static int onefs_get_real_filename(vfs_handle_struct *handle, const char *path,
				   const char *name, TALLOC_CTX *mem_ctx,
				   char **found_name)
{
	SMB_STRUCT_STAT sb;
	struct stat_extra se;
	int result;
	char *full_name = NULL;

	ZERO_STRUCT(se);
	se.se_version = ESTAT_CURRENT_VERSION;
	se.se_flags = ESTAT_CASE_INSENSITIVE | ESTAT_SYMLINK_NOFOLLOW;

	if (*path != '\0') {
		if (!(full_name = talloc_asprintf(mem_ctx, "%s/%s", path, name))) {
			errno = ENOMEM;
			DEBUG(2, ("talloc_asprintf failed\n"));
			result = -1;
			goto done;
		}
	}

	if ((result = estat(full_name ? full_name : name, &sb, &se)) != 0) {
		DEBUG(2, ("error calling estat: %s\n", strerror(errno)));
		goto done;
	}

	*found_name = talloc_strdup(mem_ctx, se.se_realname);
	if (*found_name == NULL) {
		errno = ENOMEM;
		result = -1;
		goto done;
	}

done:
	TALLOC_FREE(full_name);
	return result;
}

static int onefs_ntimes(vfs_handle_struct *handle, const char *fname,
			struct smb_file_time *ft)
{
	int flags = 0;
	struct timespec times[3];

	if (!null_timespec(ft->atime)) {
		flags |= VT_ATIME;
		times[0] = ft->atime;
		DEBUG(6,("**** onefs_ntimes: actime: %s.%d\n",
			time_to_asc(convert_timespec_to_time_t(ft->atime)),
			ft->atime.tv_nsec));
	}

	if (!null_timespec(ft->mtime)) {
		flags |= VT_MTIME;
		times[1] = ft->mtime;
		DEBUG(6,("**** onefs_ntimes: modtime: %s.%d\n",
			time_to_asc(convert_timespec_to_time_t(ft->mtime)),
			ft->mtime.tv_nsec));
	}

	if (!null_timespec(ft->create_time)) {
		flags |= VT_BTIME;
		times[2] = ft->create_time;
		DEBUG(6,("**** onefs_ntimes: createtime: %s.%d\n",
		   time_to_asc(convert_timespec_to_time_t(ft->create_time)),
		   ft->create_time.tv_nsec));
	}

	return onefs_vtimes_streams(handle, fname, flags, times);
}

static uint32_t onefs_fs_capabilities(struct vfs_handle_struct *handle)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle) | FILE_NAMED_STREAMS;
}

static vfs_op_tuple onefs_ops[] = {
	{SMB_VFS_OP(onefs_connect), SMB_VFS_OP_CONNECT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_fs_capabilities), SMB_VFS_OP_FS_CAPABILITIES,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_opendir), SMB_VFS_OP_OPENDIR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_readdir), SMB_VFS_OP_READDIR,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_seekdir), SMB_VFS_OP_SEEKDIR,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_telldir), SMB_VFS_OP_TELLDIR,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_rewinddir), SMB_VFS_OP_REWINDDIR,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_mkdir), SMB_VFS_OP_MKDIR,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_closedir), SMB_VFS_OP_CLOSEDIR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_init_search_op), SMB_VFS_OP_INIT_SEARCH_OP,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_open), SMB_VFS_OP_OPEN,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_create_file), SMB_VFS_OP_CREATE_FILE,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_close), SMB_VFS_OP_CLOSE,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_recvfile), SMB_VFS_OP_RECVFILE,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_rename), SMB_VFS_OP_RENAME,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_stat), SMB_VFS_OP_STAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_fstat), SMB_VFS_OP_FSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_lstat), SMB_VFS_OP_LSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_get_alloc_size), SMB_VFS_OP_GET_ALLOC_SIZE,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_unlink), SMB_VFS_OP_UNLINK,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_ntimes), SMB_VFS_OP_NTIMES,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_chflags), SMB_VFS_OP_CHFLAGS,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_streaminfo), SMB_VFS_OP_STREAMINFO,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_brl_lock_windows), SMB_VFS_OP_BRL_LOCK_WINDOWS,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_brl_unlock_windows), SMB_VFS_OP_BRL_UNLOCK_WINDOWS,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_brl_cancel_windows), SMB_VFS_OP_BRL_CANCEL_WINDOWS,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_fget_nt_acl), SMB_VFS_OP_FGET_NT_ACL,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_get_nt_acl), SMB_VFS_OP_GET_NT_ACL,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_fset_nt_acl), SMB_VFS_OP_FSET_NT_ACL,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_statvfs), SMB_VFS_OP_STATVFS,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_get_real_filename), SMB_VFS_OP_GET_REAL_FILENAME,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_onefs_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "onefs",
				onefs_ops);
}
