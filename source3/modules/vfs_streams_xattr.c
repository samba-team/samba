/*
 * Store streams in xattrs
 *
 * Copyright (C) Volker Lendecke, 2008
 *
 * Partly based on James Peach's Darwin module, which is
 *
 * Copyright (C) James Peach 2006-2007
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
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "lib/util/tevent_unix.h"
#include "librpc/gen_ndr/ioctl.h"
#include "hash_inode.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct streams_xattr_config {
	const char *prefix;
	size_t prefix_len;
	size_t max_extents;
	bool store_stream_type;
};

struct stream_io {
	char *base;
	char *xattr_name;
	void *fsp_name_ptr;
	files_struct *fsp;
	vfs_handle_struct *handle;
};

static ssize_t fgetxattr_multi(const struct streams_xattr_config *config,
			       struct files_struct *fsp,
			       const char *name,
			       void *value,
			       size_t size)
{
	ssize_t ret = SMB_VFS_FGETXATTR(fsp, name, value, size);
	return ret;
}

static int fsetxattr_multi(const struct streams_xattr_config *config,
			   struct files_struct *fsp,
			   const char *name,
			   const void *value,
			   size_t size,
			   int flags)
{
	int ret = SMB_VFS_FSETXATTR(fsp, name, value, size, flags);
	return ret;
}

static int fremovexattr_multi(const struct streams_xattr_config *config,
			      struct files_struct *fsp,
			      const char *name)
{
	int ret = SMB_VFS_FREMOVEXATTR(fsp, name);
	return ret;
}

static int streams_xattr_get_ea_value_fsp(
	TALLOC_CTX *mem_ctx,
	const struct streams_xattr_config *config,
	files_struct *fsp,
	const char *ea_name,
	char **_val)
{
	/* Get the value of this xattr. Max size is 64k. */
	size_t attr_size = 256;
	char *val = NULL;
	ssize_t sizeret;
	size_t max_xattr_size = 0;
	bool refuse;

	if (fsp == NULL) {
		return EINVAL;
	}
	refuse = refuse_symlink_fsp(fsp);
	if (refuse) {
		return EACCES;
	}

	max_xattr_size = lp_smbd_max_xattr_size(SNUM(fsp->conn));

again:

	val = talloc_realloc(mem_ctx, val, char, attr_size);
	if (!val) {
		return ENOMEM;
	}

	sizeret = fgetxattr_multi(config, fsp, ea_name, val, attr_size);
	if (sizeret == -1 && errno == ERANGE && attr_size < max_xattr_size) {
		attr_size = max_xattr_size;
		goto again;
	}

	if (sizeret == -1) {
		int err = errno;
		TALLOC_FREE(val);
		return err;
	}

	DBG_DEBUG("EA %s is of length %zd\n", ea_name, sizeret);
	dump_data(10, (uint8_t *)val, sizeret);

	val = talloc_realloc(mem_ctx, val, char, sizeret);
	*_val = val;

	return 0;
}

static ssize_t get_xattr_size_fsp(const struct streams_xattr_config *config,
				  struct files_struct *fsp,
			          const char *xattr_name)
{
	int ret;
	char *val = NULL;
	ssize_t result;

	ret = streams_xattr_get_ea_value_fsp(
		talloc_tos(), config, fsp, xattr_name, &val);
	if (ret != 0) {
		return -1;
	}

	result = talloc_get_size(val);
	TALLOC_FREE(val);
	return result;
}

/**
 * Given a stream name, populate xattr_name with the xattr name to use for
 * accessing the stream.
 */
static int streams_xattr_get_name(vfs_handle_struct *handle,
				  TALLOC_CTX *ctx,
				  const char *stream_name,
				  char **xattr_name)
{
	size_t stream_name_len = strlen(stream_name);
	char *stype;
	struct streams_xattr_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				return EACCES);

	SMB_ASSERT(stream_name[0] == ':');
	stream_name += 1;

	/*
	 * With vfs_fruit option "fruit:encoding = native" we're
	 * already converting stream names that contain illegal NTFS
	 * characters from their on-the-wire Unicode Private Range
	 * encoding to their native ASCII representation.
	 *
	 * As as result the name of xattrs storing the streams (via
	 * vfs_streams_xattr) may contain a colon, so we have to use
	 * strrchr_m() instead of strchr_m() for matching the stream
	 * type suffix.
	 *
	 * In check_path_syntax() we've already ensured the streamname
	 * we got from the client is valid.
	 */
	stype = strrchr_m(stream_name, ':');

	if (stype) {
		/*
		 * We only support one stream type: "$DATA"
		 */
		if (strcasecmp_m(stype, ":$DATA") != 0) {
			return EINVAL;
		}

		/* Split name and type */
		stream_name_len = (stype - stream_name);
	}

	*xattr_name = talloc_asprintf(ctx, "%s%.*s%s",
				      config->prefix,
				      (int)stream_name_len,
				      stream_name,
				      config->store_stream_type ? ":$DATA" : "");
	if (*xattr_name == NULL) {
		return ENOMEM;
	}

	DBG_DEBUG("%s, stream_name: %s\n", *xattr_name, stream_name);

	return 0;
}

static bool streams_xattr_recheck(struct stream_io *sio)
{
	int ret;
	char *xattr_name = NULL;

	if (sio->fsp->fsp_name == sio->fsp_name_ptr) {
		return true;
	}

	if (sio->fsp->fsp_name->stream_name == NULL) {
		/* how can this happen */
		errno = EINVAL;
		return false;
	}

	ret = streams_xattr_get_name(sio->handle,
				     talloc_tos(),
				     sio->fsp->fsp_name->stream_name,
				     &xattr_name);
	if (ret != 0) {
		return false;
	}

	TALLOC_FREE(sio->xattr_name);
	TALLOC_FREE(sio->base);
	sio->xattr_name = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(sio->handle, sio->fsp),
					xattr_name);
	if (sio->xattr_name == NULL) {
		DBG_DEBUG("sio->xattr_name==NULL\n");
		return false;
	}
	TALLOC_FREE(xattr_name);

	sio->base = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(sio->handle, sio->fsp),
				  sio->fsp->fsp_name->base_name);
	if (sio->base == NULL) {
		DBG_DEBUG("sio->base==NULL\n");
		return false;
	}

	sio->fsp_name_ptr = sio->fsp->fsp_name;

	return true;
}

static int streams_xattr_fstat(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_STRUCT_STAT *sbuf)
{
	struct streams_xattr_config *config = NULL;
	int ret = -1;
	struct stream_io *io = (struct stream_io *)
		VFS_FETCH_FSP_EXTENSION(handle, fsp);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				return -1);

	if (io == NULL || !fsp_is_alternate_stream(fsp)) {
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	DBG_DEBUG("streams_xattr_fstat called for %s\n", fsp_str_dbg(io->fsp));

	if (!streams_xattr_recheck(io)) {
		return -1;
	}

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp->base_fsp, sbuf);
	if (ret == -1) {
		return -1;
	}

	sbuf->st_ex_size = get_xattr_size_fsp(config,
					      fsp->base_fsp,
					      io->xattr_name);
	if (sbuf->st_ex_size == -1) {
		SET_STAT_INVALID(*sbuf);
		return -1;
	}

	DBG_DEBUG("sbuf->st_ex_size = %jd\n", (intmax_t)sbuf->st_ex_size);

	sbuf->st_ex_ino = hash_inode(sbuf, io->xattr_name);
	sbuf->st_ex_mode &= ~S_IFMT;
	sbuf->st_ex_mode &= ~S_IFDIR;
        sbuf->st_ex_mode |= S_IFREG;
        sbuf->st_ex_blocks = sbuf->st_ex_size / STAT_ST_BLOCKSIZE + 1;

	return 0;
}

static int streams_xattr_stat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	struct streams_xattr_config *config = NULL;
	NTSTATUS status;
	int ret;
	int result = -1;
	char *xattr_name = NULL;
	char *tmp_stream_name = NULL;
	struct smb_filename *pathref = NULL;
	struct files_struct *fsp = smb_fname->fsp;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				return -1);

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	/* Note if lp_posix_paths() is true, we can never
	 * get here as is_named_stream() is
	 * always false. So we never need worry about
	 * not following links here. */

	/* Populate the stat struct with info from the base file. */
	tmp_stream_name = smb_fname->stream_name;
	smb_fname->stream_name = NULL;
	result = SMB_VFS_NEXT_STAT(handle, smb_fname);
	smb_fname->stream_name = tmp_stream_name;

	if (result == -1) {
		return -1;
	}

	/* Derive the xattr name to lookup. */
	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	/* Augment the base file's stat information before returning. */
	if (fsp == NULL) {
		status = synthetic_pathref(talloc_tos(),
					   handle->conn->cwd_fsp,
					   smb_fname->base_name,
					   NULL,
					   NULL,
					   smb_fname->twrp,
					   smb_fname->flags,
					   &pathref);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(xattr_name);
			SET_STAT_INVALID(smb_fname->st);
			errno = ENOENT;
			return -1;
		}
		fsp = pathref->fsp;
	} else {
		fsp = fsp->base_fsp;
	}

	smb_fname->st.st_ex_size = get_xattr_size_fsp(config, fsp, xattr_name);
	if (smb_fname->st.st_ex_size == -1) {
		TALLOC_FREE(xattr_name);
		TALLOC_FREE(pathref);
		SET_STAT_INVALID(smb_fname->st);
		errno = ENOENT;
		return -1;
	}

	smb_fname->st.st_ex_ino = hash_inode(&smb_fname->st, xattr_name);
	smb_fname->st.st_ex_mode &= ~S_IFMT;
        smb_fname->st.st_ex_mode |= S_IFREG;
        smb_fname->st.st_ex_blocks =
	    smb_fname->st.st_ex_size / STAT_ST_BLOCKSIZE + 1;

	TALLOC_FREE(xattr_name);
	TALLOC_FREE(pathref);
	return 0;
}

static int streams_xattr_lstat(vfs_handle_struct *handle,
			       struct smb_filename *smb_fname)
{
	if (is_named_stream(smb_fname)) {
		/*
		 * There can never be EA's on a symlink.
		 * Windows will never see a symlink, and
		 * in SMB_FILENAME_POSIX_PATH mode we don't
		 * allow EA's on a symlink.
		 */
		SET_STAT_INVALID(smb_fname->st);
		errno = ENOENT;
		return -1;
	}
	return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
}

static int streams_xattr_fstatat(struct vfs_handle_struct *handle,
				 const struct files_struct *dirfsp,
				 const struct smb_filename *smb_fname,
				 SMB_STRUCT_STAT *sbuf,
				 int flags)
{
	struct streams_xattr_config *config = NULL;
	char *xattr_name = NULL;
	struct smb_filename *pathref = NULL;
	struct files_struct *fsp = smb_fname->fsp;
	ssize_t size;
	NTSTATUS status;
	int ret = -1;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				return -1);

	DBG_DEBUG("called for [%s/%s]\n",
		  dirfsp->fsp_name->base_name,
		  smb_fname_str_dbg(smb_fname));

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_FSTATAT(
			handle, dirfsp, smb_fname, sbuf, flags);
	}

	SET_STAT_INVALID(*sbuf);

	/* Derive the xattr name to lookup. */
	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		ret = -1;
		goto done;
	}

	if (fsp == NULL) {
		status = synthetic_pathref(talloc_tos(),
					   dirfsp,
					   smb_fname->base_name,
					   NULL,
					   NULL,
					   smb_fname->twrp,
					   smb_fname->flags,
					   &pathref);
		if (!NT_STATUS_IS_OK(status)) {
			errno = ENOENT;
			ret = -1;
			goto done;
		}
		fsp = pathref->fsp;
	} else {
		fsp = fsp->base_fsp;
	}

	*sbuf = fsp->fsp_name->st;

	size = get_xattr_size_fsp(config, fsp, xattr_name);
	if (size == -1) {
		errno = ENOENT;
		ret = -1;
		goto done;
	}
	sbuf->st_ex_size = size;
	sbuf->st_ex_ino = hash_inode(sbuf, xattr_name);
	sbuf->st_ex_mode &= ~S_IFMT;
	sbuf->st_ex_mode |= S_IFREG;
	sbuf->st_ex_blocks = sbuf->st_ex_size / STAT_ST_BLOCKSIZE + 1;

done:
	{
		int err = errno;
		TALLOC_FREE(pathref);
		TALLOC_FREE(xattr_name);
		errno = err;
	}
	return ret;
}

static int streams_xattr_openat(struct vfs_handle_struct *handle,
				const struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				files_struct *fsp,
				const struct vfs_open_how *how)
{
	struct streams_xattr_config *config = NULL;
	struct stream_io *sio = NULL;
	char *val = NULL;
	char *xattr_name = NULL;
	int fakefd = -1;
	bool set_empty_xattr = false;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	DBG_DEBUG("called for %s with flags 0x%x\n",
		  smb_fname_str_dbg(smb_fname),
		  how->flags);

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname,
					   fsp,
					   how);
	}

	if ((how->resolve & ~VFS_OPEN_HOW_WITH_BACKUP_INTENT) != 0) {
		errno = ENOSYS;
		return -1;
	}

	SMB_ASSERT(fsp_is_alternate_stream(fsp));
	SMB_ASSERT(dirfsp == NULL);

	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		goto fail;
	}

	ret = streams_xattr_get_ea_value_fsp(
		talloc_tos(), config, fsp->base_fsp, xattr_name, &val);
	if (ret != 0) {
		DBG_DEBUG("streams_xattr_get_ea_value_fsp returned %s\n",
			  strerror(ret));

		if (ret != ENOATTR) {
			/*
			 * The base file is not there. This is an error even if
			 * we got O_CREAT, the higher levels should have created
			 * the base file for us.
			 */
			DBG_DEBUG("base file %s not around, "
				  "returning ENOENT\n",
				  smb_fname->base_name);
			errno = ENOENT;
			goto fail;
		}

		if (!(how->flags & O_CREAT)) {
			errno = ENOENT;
			goto fail;
		}

		set_empty_xattr = true;
	}

	TALLOC_FREE(val);

	if (how->flags & O_TRUNC) {
		set_empty_xattr = true;
	}

	if (set_empty_xattr) {
		/*
		 * The attribute does not exist or needs to be truncated
		 */

		/*
		 * Darn, xattrs need at least 1 byte
		 */
		char null = '\0';

		DEBUG(10, ("creating or truncating attribute %s on file %s\n",
			   xattr_name, smb_fname->base_name));

		ret = fsetxattr_multi(config,
				      fsp->base_fsp,
				      xattr_name,
				      &null,
				      sizeof(null),
				      how->flags & O_EXCL ? XATTR_CREATE : 0);
		if (ret != 0) {
			goto fail;
		}
	}

	fakefd = vfs_fake_fd();

        sio = VFS_ADD_FSP_EXTENSION(handle, fsp, struct stream_io, NULL);
        if (sio == NULL) {
                errno = ENOMEM;
                goto fail;
        }

        sio->xattr_name = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
					xattr_name);
	if (sio->xattr_name == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	/*
	 * so->base needs to be a copy of fsp->fsp_name->base_name,
	 * making it identical to streams_xattr_recheck(). If the
	 * open is changing directories, fsp->fsp_name->base_name
	 * will be the full path from the share root, whilst
	 * smb_fname will be relative to the $cwd.
	 */
        sio->base = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
				  fsp->fsp_name->base_name);
	if (sio->base == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	sio->fsp_name_ptr = fsp->fsp_name;
	sio->handle = handle;
	sio->fsp = fsp;

	return fakefd;

 fail:
	if (fakefd >= 0) {
		vfs_fake_fd_close(fakefd);
		fakefd = -1;
	}

	return -1;
}

static int streams_xattr_close(vfs_handle_struct *handle,
			       files_struct *fsp)
{
	int ret;
	int fd;

	fd = fsp_get_pathref_fd(fsp);

	DBG_DEBUG("called [%s] fd [%d]\n",
		  smb_fname_str_dbg(fsp->fsp_name),
		  fd);

	if (!fsp_is_alternate_stream(fsp)) {
		return SMB_VFS_NEXT_CLOSE(handle, fsp);
	}

	ret = vfs_fake_fd_close(fd);
	fsp_set_fd(fsp, -1);

	return ret;
}

static int streams_xattr_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	struct streams_xattr_config *config;
	NTSTATUS status;
	int ret = -1;
	char *xattr_name = NULL;
	char *raw_stream_name = NULL;
	struct smb_filename *pathref = NULL;
	struct files_struct *fsp = smb_fname->fsp;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				return -1);

	if (!is_named_stream(smb_fname)) {
		return SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
	}

	/* A stream can never be rmdir'ed */
	SMB_ASSERT((flags & AT_REMOVEDIR) == 0);

	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname->stream_name,
				     &xattr_name);
	if (ret != 0) {
		errno = ret;
		goto fail;
	}

	if (fsp == NULL) {
		status = synthetic_pathref(talloc_tos(),
					handle->conn->cwd_fsp,
					smb_fname->base_name,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags,
					&pathref);
		if (!NT_STATUS_IS_OK(status)) {
			errno = ENOENT;
			goto fail;
		}
		fsp = pathref->fsp;
	} else {
		SMB_ASSERT(fsp_is_alternate_stream(smb_fname->fsp));
		fsp = fsp->base_fsp;
	}

	ret = fremovexattr_multi(config, fsp, xattr_name);

	if ((ret == -1) && (errno == ENOATTR)) {
		errno = ENOENT;
		goto fail;
	}

	ret = 0;

 fail:
	TALLOC_FREE(raw_stream_name);
	TALLOC_FREE(xattr_name);
	TALLOC_FREE(pathref);
	return ret;
}

static int streams_xattr_renameat(vfs_handle_struct *handle,
				files_struct *srcfsp,
				const struct smb_filename *smb_fname_src,
				files_struct *dstfsp,
				const struct smb_filename *smb_fname_dst,
				const struct vfs_rename_how *how)
{
	struct streams_xattr_config *config = NULL;
	NTSTATUS status;
	int ret = -1;
	char *src_xattr_name = NULL;
	char *dst_xattr_name = NULL;
	bool src_is_stream, dst_is_stream;
	ssize_t oret;
	ssize_t nret;
	char *val = NULL;
	struct smb_filename *pathref_src = NULL;
	struct smb_filename *pathref_dst = NULL;
	struct smb_filename *full_src = NULL;
	struct smb_filename *full_dst = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				goto fail;);

	src_is_stream = is_ntfs_stream_smb_fname(smb_fname_src);
	dst_is_stream = is_ntfs_stream_smb_fname(smb_fname_dst);

	if (!src_is_stream && !dst_is_stream) {
		return SMB_VFS_NEXT_RENAMEAT(handle,
					srcfsp,
					smb_fname_src,
					dstfsp,
					smb_fname_dst,
					how);
	}

	if (how->flags != 0) {
		errno = EINVAL;
		goto done;
	}

	/* For now don't allow renames from or to the default stream. */
	if (is_ntfs_default_stream_smb_fname(smb_fname_src) ||
	    is_ntfs_default_stream_smb_fname(smb_fname_dst)) {
		errno = ENOSYS;
		goto done;
	}

	/* Don't rename if the streams are identical. */
	if (strequal(smb_fname_src->stream_name, smb_fname_dst->stream_name)) {
		goto done;
	}

	/* Get the xattr names. */
	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname_src->stream_name,
				     &src_xattr_name);
	if (ret != 0) {
		errno = ret;
		goto fail;
	}
	ret = streams_xattr_get_name(handle,
				     talloc_tos(),
				     smb_fname_dst->stream_name,
				     &dst_xattr_name);
	if (ret != 0) {
		errno = ret;
		goto fail;
	}

	full_src = full_path_from_dirfsp_atname(talloc_tos(),
						srcfsp,
						smb_fname_src);
	if (full_src == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	full_dst = full_path_from_dirfsp_atname(talloc_tos(),
						dstfsp,
						smb_fname_dst);
	if (full_dst == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	/* Get a pathref for full_src (base file, no stream name). */
	status = synthetic_pathref(talloc_tos(),
				handle->conn->cwd_fsp,
				full_src->base_name,
				NULL,
				NULL,
				full_src->twrp,
				full_src->flags,
				&pathref_src);
	if (!NT_STATUS_IS_OK(status)) {
		errno = ENOENT;
		goto fail;
	}

	/* Read the old stream from the base file fsp. */
	ret = streams_xattr_get_ea_value_fsp(
		talloc_tos(), config, pathref_src->fsp, src_xattr_name, &val);
	if (ret != 0) {
		errno = ret;
		goto fail;
	}

	/* Get a pathref for full_dst (base file, no stream name). */
	status = synthetic_pathref(talloc_tos(),
				handle->conn->cwd_fsp,
				full_dst->base_name,
				NULL,
				NULL,
				full_dst->twrp,
				full_dst->flags,
				&pathref_dst);
	if (!NT_STATUS_IS_OK(status)) {
		errno = ENOENT;
		goto fail;
	}

	/* (Over)write the new stream on the base file fsp. */
	nret = fsetxattr_multi(config,
			       pathref_dst->fsp,
			       dst_xattr_name,
			       val,
			       talloc_get_size(val),
			       0);
	if (nret < 0) {
		if (errno == ENOATTR) {
			errno = ENOENT;
		}
		goto fail;
	}

	/*
	 * Remove the old stream from the base file fsp.
	 */
	oret = fremovexattr_multi(config, pathref_src->fsp, src_xattr_name);
	if (oret < 0) {
		if (errno == ENOATTR) {
			errno = ENOENT;
		}
		goto fail;
	}

 done:
	errno = 0;
	ret = 0;
 fail:
	TALLOC_FREE(pathref_src);
	TALLOC_FREE(pathref_dst);
	TALLOC_FREE(full_src);
	TALLOC_FREE(full_dst);
	TALLOC_FREE(src_xattr_name);
	TALLOC_FREE(dst_xattr_name);
	return ret;
}

static NTSTATUS walk_xattr_streams(vfs_handle_struct *handle,
				files_struct *fsp,
				const struct smb_filename *smb_fname,
				bool (*fn)(struct ea_struct *ea,
					void *private_data),
				void *private_data)
{
	NTSTATUS status;
	char **names;
	size_t i, num_names;
	struct streams_xattr_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return NT_STATUS_UNSUCCESSFUL);

	status = get_ea_names_from_fsp(talloc_tos(),
				smb_fname->fsp,
				&names,
				&num_names);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i=0; i<num_names; i++) {
		char *val = NULL;
		struct ea_struct ea;
		int ret;

		/*
		 * We want to check with samba_private_attr_name()
		 * whether the xattr name is a private one,
		 * unfortunately it flags xattrs that begin with the
		 * default streams prefix as private.
		 *
		 * By only calling samba_private_attr_name() in case
		 * the xattr does NOT begin with the default prefix,
		 * we know that if it returns 'true' it definitely one
		 * of our internal xattr like "user.DOSATTRIB".
		 */
		if (strncasecmp_m(names[i], SAMBA_XATTR_DOSSTREAM_PREFIX,
				  strlen(SAMBA_XATTR_DOSSTREAM_PREFIX)) != 0) {
			if (samba_private_attr_name(names[i])) {
				continue;
			}
		}

		if (strncmp(names[i], config->prefix,
			    config->prefix_len) != 0) {
			continue;
		}

		ret = streams_xattr_get_ea_value_fsp(
			names, config, smb_fname->fsp, names[i], &val);
		if (ret != 0) {
			DBG_DEBUG("Could not get ea %s for file %s: %s\n",
				  names[i],
				  smb_fname->base_name,
				  strerror(ret));
			continue;
		}

		ea.value.data = (uint8_t *)val;
		ea.value.length = talloc_get_size(val);

		ea.name = talloc_asprintf(
			ea.value.data, ":%s%s",
			names[i] + config->prefix_len,
			config->store_stream_type ? "" : ":$DATA");
		if (ea.name == NULL) {
			DEBUG(0, ("talloc failed\n"));
			continue;
		}

		if (!fn(&ea, private_data)) {
			TALLOC_FREE(ea.value.data);
			return NT_STATUS_OK;
		}

		TALLOC_FREE(val);
	}

	TALLOC_FREE(names);
	return NT_STATUS_OK;
}

static bool add_one_stream(TALLOC_CTX *mem_ctx, unsigned int *num_streams,
			   struct stream_struct **streams,
			   const char *name, off_t size,
			   off_t alloc_size)
{
	struct stream_struct *tmp;

	tmp = talloc_realloc(mem_ctx, *streams, struct stream_struct,
				   (*num_streams)+1);
	if (tmp == NULL) {
		return false;
	}

	tmp[*num_streams].name = talloc_strdup(tmp, name);
	if (tmp[*num_streams].name == NULL) {
		return false;
	}

	tmp[*num_streams].size = size;
	tmp[*num_streams].alloc_size = alloc_size;

	*streams = tmp;
	*num_streams += 1;
	return true;
}

struct streaminfo_state {
	TALLOC_CTX *mem_ctx;
	vfs_handle_struct *handle;
	unsigned int num_streams;
	struct stream_struct *streams;
	NTSTATUS status;
};

static bool collect_one_stream(struct ea_struct *ea, void *private_data)
{
	struct streaminfo_state *state =
		(struct streaminfo_state *)private_data;

	if (!add_one_stream(state->mem_ctx,
			    &state->num_streams, &state->streams,
			    ea->name, ea->value.length-1,
			    smb_roundup(state->handle->conn,
					ea->value.length-1))) {
		state->status = NT_STATUS_NO_MEMORY;
		return false;
	}

	return true;
}

static NTSTATUS streams_xattr_fstreaminfo(vfs_handle_struct *handle,
					 struct files_struct *fsp,
					 TALLOC_CTX *mem_ctx,
					 unsigned int *pnum_streams,
					 struct stream_struct **pstreams)
{
	NTSTATUS status;
	struct streaminfo_state state;

	state.streams = *pstreams;
	state.num_streams = *pnum_streams;
	state.mem_ctx = mem_ctx;
	state.handle = handle;
	state.status = NT_STATUS_OK;

	status = walk_xattr_streams(handle,
				    fsp,
				    fsp->fsp_name,
				    collect_one_stream,
				    &state);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state.streams);
		return status;
	}

	if (!NT_STATUS_IS_OK(state.status)) {
		TALLOC_FREE(state.streams);
		return state.status;
	}

	*pnum_streams = state.num_streams;
	*pstreams = state.streams;

	return SMB_VFS_NEXT_FSTREAMINFO(handle,
			fsp,
			mem_ctx,
			pnum_streams,
			pstreams);
}

static uint32_t streams_xattr_fs_capabilities(struct vfs_handle_struct *handle,
			enum timestamp_set_resolution *p_ts_res)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res) | FILE_NAMED_STREAMS;
}

static int streams_xattr_connect(vfs_handle_struct *handle,
				 const char *service, const char *user)
{
	struct streams_xattr_config *config;
	const char *default_prefix = SAMBA_XATTR_DOSSTREAM_PREFIX;
	const char *prefix;
	int rc, max_xattrs;

	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (rc != 0) {
		return rc;
	}

	config = talloc_zero(handle->conn, struct streams_xattr_config);
	if (config == NULL) {
		DEBUG(1, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	prefix = lp_parm_const_string(SNUM(handle->conn),
				      "streams_xattr", "prefix",
				      default_prefix);
	config->prefix = talloc_strdup(config, prefix);
	if (config->prefix == NULL) {
		DEBUG(1, ("talloc_strdup() failed\n"));
		errno = ENOMEM;
		return -1;
	}
	config->prefix_len = strlen(config->prefix);
	DEBUG(10, ("streams_xattr using stream prefix: %s\n", config->prefix));

	if (config->prefix_len == 0) {
		DBG_WARNING("Empty prefix not valid\n");
		errno = EINVAL;
		return -1;
	}

	config->store_stream_type = lp_parm_bool(SNUM(handle->conn),
						 "streams_xattr",
						 "store_stream_type",
						 true);

	max_xattrs = lp_parm_int(SNUM(handle->conn),
				 "streams_xattr",
				 "max xattrs per stream",
				 1);
	if ((max_xattrs < 1) || (max_xattrs > 16)) {
		DBG_WARNING("\"max xattrs per stream\"=%d invalid: "
			    "Between 1 and 16 possible\n",
			    max_xattrs);
		errno = EINVAL;
		return -1;
	}
	config->max_extents = max_xattrs - 1;

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct stream_xattr_config,
				return -1);

	return 0;
}

static ssize_t streams_xattr_pwrite(vfs_handle_struct *handle,
				    files_struct *fsp, const void *data,
				    size_t n, off_t offset)
{
	struct streams_xattr_config *config = NULL;
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	char *val = NULL;
	size_t len;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	DBG_DEBUG("offset=%jd, size=%zu\n", (intmax_t)offset, n);

	if (sio == NULL) {
		return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	}

	if ((offset < 0) || ((offset + n) < n)) {
		errno = EOVERFLOW;
		return -1;
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	if ((offset + n) >= lp_smbd_max_xattr_size(SNUM(handle->conn))) {
		/*
		 * Requested write is beyond what can be read based on
		 * samba configuration.
		 * ReFS returns STATUS_FILESYSTEM_LIMITATION, which causes
		 * entire file to be skipped by File Explorer. VFAT returns
		 * NT_STATUS_OBJECT_NAME_COLLISION causes user to be prompted
		 * to skip writing metadata, but copy data.
		 */
		DBG_ERR("Write to xattr [%s] on file [%s] exceeds maximum "
			"supported extended attribute size. "
			"Depending on filesystem type and operating system "
			"(OS) specifics, this value may be increased using "
			"the value of the parameter: "
			"smbd max xattr size = <bytes>. Consult OS and "
			"filesystem manpages prior to increasing this limit.\n",
			sio->xattr_name, sio->base);
		errno = EOVERFLOW;
		return -1;
	}

	ret = streams_xattr_get_ea_value_fsp(
		talloc_tos(), config, fsp->base_fsp, sio->xattr_name, &val);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	len = talloc_get_size(val) - 1;

	if ((offset + n) > len) {
		char *tmp = NULL;

		tmp = talloc_realloc_zero(talloc_tos(),
					  val,
					  char,
					  offset + n + 1);
		if (tmp == NULL) {
			TALLOC_FREE(val);
			errno = ENOMEM;
			return -1;
                }
		val = tmp;

		val[offset + n] = '\0';
	}

	memcpy(val + offset, data, n);

	ret = fsetxattr_multi(config,
			      fsp->base_fsp,
			      sio->xattr_name,
			      val,
			      talloc_get_size(val),
			      0);
	TALLOC_FREE(val);

	if (ret == -1) {
		return -1;
	}

	return n;
}

static ssize_t streams_xattr_pread(vfs_handle_struct *handle,
				   files_struct *fsp, void *data,
				   size_t n, off_t offset)
{
	struct streams_xattr_config *config = NULL;
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	char *val = NULL;
	int ret;
	size_t length, overlap;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct streams_xattr_config,
				return -1);

	DBG_DEBUG("offset=%jd, size=%zu\n", (intmax_t)offset, n);

	if (sio == NULL) {
		return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	}

	if ((offset < 0) || ((offset + n) < n)) {
		errno = EOVERFLOW;
		return -1;
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	ret = streams_xattr_get_ea_value_fsp(
		talloc_tos(), config, fsp->base_fsp, sio->xattr_name, &val);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	length = talloc_get_size(val);

	if (length < 1) {
		errno = EINVAL;
		return -1;
	}

	length -= 1;

	DBG_DEBUG("streams_xattr_get_ea_value_fsp returned %zu bytes\n",
		  length);

	/* Attempt to read past EOF. */
        if (length <= offset) {
                return 0;
        }

        overlap = (offset + n) > length ? (length - offset) : n;
	memcpy(data, val + offset, overlap);

	TALLOC_FREE(val);
	return overlap;
}

struct streams_xattr_pread_state {
	ssize_t nread;
	struct vfs_aio_state vfs_aio_state;
};

static void streams_xattr_pread_done(struct tevent_req *subreq);

static struct tevent_req *streams_xattr_pread_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	void *data,
	size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct streams_xattr_pread_state *state = NULL;
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct streams_xattr_pread_state);
	if (req == NULL) {
		return NULL;
	}

	if (sio == NULL) {
		subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp,
						 data, n, offset);
		if (tevent_req_nomem(req, subreq)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, streams_xattr_pread_done, req);
		return req;
	}

	state->nread = SMB_VFS_PREAD(fsp, data, n, offset);
	if (state->nread != n) {
		if (state->nread != -1) {
			errno = EIO;
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void streams_xattr_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct streams_xattr_pread_state *state = tevent_req_data(
		req, struct streams_xattr_pread_state);

	state->nread = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (tevent_req_error(req, state->vfs_aio_state.error)) {
		return;
	}
	tevent_req_done(req);
}

static ssize_t streams_xattr_pread_recv(struct tevent_req *req,
					struct vfs_aio_state *vfs_aio_state)
{
	struct streams_xattr_pread_state *state = tevent_req_data(
		req, struct streams_xattr_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->nread;
}

struct streams_xattr_pwrite_state {
	ssize_t nwritten;
	struct vfs_aio_state vfs_aio_state;
};

static void streams_xattr_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *streams_xattr_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	const void *data,
	size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct streams_xattr_pwrite_state *state = NULL;
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct streams_xattr_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	if (sio == NULL) {
		subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp,
						  data, n, offset);
		if (tevent_req_nomem(req, subreq)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, streams_xattr_pwrite_done, req);
		return req;
	}

	state->nwritten = SMB_VFS_PWRITE(fsp, data, n, offset);
	if (state->nwritten != n) {
		if (state->nwritten != -1) {
			errno = EIO;
		}
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void streams_xattr_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct streams_xattr_pwrite_state *state = tevent_req_data(
		req, struct streams_xattr_pwrite_state);

	state->nwritten = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (tevent_req_error(req, state->vfs_aio_state.error)) {
		return;
	}
	tevent_req_done(req);
}

static ssize_t streams_xattr_pwrite_recv(struct tevent_req *req,
					 struct vfs_aio_state *vfs_aio_state)
{
	struct streams_xattr_pwrite_state *state = tevent_req_data(
		req, struct streams_xattr_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->nwritten;
}

static int streams_xattr_ftruncate(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					off_t offset)
{
	struct streams_xattr_config *config = NULL;
	int ret;
	char *tmp;
	char *val = NULL;
	struct stream_io *sio = (struct stream_io *)
		VFS_FETCH_FSP_EXTENSION(handle, fsp);

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct streams_xattr_config,
				return -1);

	DBG_DEBUG("called for file %s offset %ju\n",
		  fsp_str_dbg(fsp),
		  (intmax_t)offset);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	ret = streams_xattr_get_ea_value_fsp(
		talloc_tos(), config, fsp->base_fsp, sio->xattr_name, &val);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	tmp = talloc_realloc_zero(talloc_tos(), val, char, offset + 1);
	if (tmp == NULL) {
		TALLOC_FREE(val);
		errno = ENOMEM;
		return -1;
	}
	val = tmp;
	val[offset] = '\0';

	ret = fsetxattr_multi(config,
			      fsp->base_fsp,
			      sio->xattr_name,
			      val,
			      talloc_get_size(val),
			      0);

	TALLOC_FREE(val);

	if (ret == -1) {
		return -1;
	}

	return 0;
}

static int streams_xattr_fallocate(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32_t mode,
					off_t offset,
					off_t len)
{
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	DBG_DEBUG("called for file %s offset %jd len=%jd\n",
		  fsp_str_dbg(fsp),
		  (intmax_t)offset,
		  (intmax_t)len);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
	}

	if (!streams_xattr_recheck(sio)) {
		return -1;
	}

	/* Let the pwrite code path handle it. */
	errno = ENOSYS;
	return -1;
}

static int streams_xattr_fchown(vfs_handle_struct *handle, files_struct *fsp,
				uid_t uid, gid_t gid)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
	}

	return 0;
}

static int streams_xattr_fchmod(vfs_handle_struct *handle,
				files_struct *fsp,
				mode_t mode)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}

	return 0;
}

static ssize_t streams_xattr_fgetxattr(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       const char *name,
				       void *value,
				       size_t size)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
	}

	errno = ENOTSUP;
	return -1;
}

static ssize_t streams_xattr_flistxattr(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					char *list,
					size_t size)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);
	}

	errno = ENOTSUP;
	return -1;
}

static int streams_xattr_fremovexattr(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      const char *name)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
	}

	errno = ENOTSUP;
	return -1;
}

static int streams_xattr_fsetxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   const char *name,
				   const void *value,
				   size_t size,
				   int flags)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value,
					      size, flags);
	}

	errno = ENOTSUP;
	return -1;
}

struct streams_xattr_fsync_state {
	int ret;
	struct vfs_aio_state vfs_aio_state;
};

static void streams_xattr_fsync_done(struct tevent_req *subreq);

static struct tevent_req *streams_xattr_fsync_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct streams_xattr_fsync_state *state = NULL;
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	req = tevent_req_create(mem_ctx, &state,
				struct streams_xattr_fsync_state);
	if (req == NULL) {
		return NULL;
	}

	if (sio == NULL) {
		subreq = SMB_VFS_NEXT_FSYNC_SEND(state, ev, handle, fsp);
		if (tevent_req_nomem(req, subreq)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, streams_xattr_fsync_done, req);
		return req;
	}

	/*
	 * There's no pathname based sync variant and we don't have access to
	 * the basefile handle, so we can't do anything here.
	 */

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void streams_xattr_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct streams_xattr_fsync_state *state = tevent_req_data(
		req, struct streams_xattr_fsync_state);

	state->ret = SMB_VFS_FSYNC_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	if (state->ret != 0) {
		tevent_req_error(req, errno);
		return;
	}

	tevent_req_done(req);
}

static int streams_xattr_fsync_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct streams_xattr_fsync_state *state = tevent_req_data(
		req, struct streams_xattr_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static bool streams_xattr_lock(vfs_handle_struct *handle,
			       files_struct *fsp,
			       int op,
			       off_t offset,
			       off_t count,
			       int type)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);
	}

	return true;
}

static bool streams_xattr_getlock(vfs_handle_struct *handle,
				  files_struct *fsp,
				  off_t *poffset,
				  off_t *pcount,
				  int *ptype,
				  pid_t *ppid)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset,
					    pcount, ptype, ppid);
	}

	errno = ENOTSUP;
	return false;
}

static int streams_xattr_filesystem_sharemode(vfs_handle_struct *handle,
					      files_struct *fsp,
					      uint32_t share_access,
					      uint32_t access_mask)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_FILESYSTEM_SHAREMODE(handle,
							 fsp,
							 share_access,
							 access_mask);
	}

	return 0;
}

static int streams_xattr_linux_setlease(vfs_handle_struct *handle,
					files_struct *fsp,
					int leasetype)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);
	}

	return 0;
}

static bool streams_xattr_strict_lock_check(struct vfs_handle_struct *handle,
					    files_struct *fsp,
					    struct lock_struct *plock)
{
	struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (sio == NULL) {
		return SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);
	}

	return true;
}

static int streams_xattr_fcntl(vfs_handle_struct *handle,
			       files_struct *fsp,
			       int cmd,
			       va_list cmd_arg)
{
	va_list dup_cmd_arg;
	void *arg;
	int ret;

	if (fsp_is_alternate_stream(fsp)) {
		switch (cmd) {
		case F_GETFL:
		case F_SETFL:
			break;
		default:
			DBG_ERR("Unsupported fcntl() cmd [%d] on [%s]\n",
				cmd, fsp_str_dbg(fsp));
			errno = EINVAL;
			return -1;
		}
	}

	va_copy(dup_cmd_arg, cmd_arg);
	arg = va_arg(dup_cmd_arg, void *);

	ret = SMB_VFS_NEXT_FCNTL(handle, fsp, cmd, arg);

	va_end(dup_cmd_arg);

	return ret;
}

static struct vfs_fn_pointers vfs_streams_xattr_fns = {
	.fs_capabilities_fn = streams_xattr_fs_capabilities,
	.connect_fn = streams_xattr_connect,
	.openat_fn = streams_xattr_openat,
	.close_fn = streams_xattr_close,
	.stat_fn = streams_xattr_stat,
	.fstat_fn = streams_xattr_fstat,
	.lstat_fn = streams_xattr_lstat,
	.fstatat_fn = streams_xattr_fstatat,
	.pread_fn = streams_xattr_pread,
	.pwrite_fn = streams_xattr_pwrite,
	.pread_send_fn = streams_xattr_pread_send,
	.pread_recv_fn = streams_xattr_pread_recv,
	.pwrite_send_fn = streams_xattr_pwrite_send,
	.pwrite_recv_fn = streams_xattr_pwrite_recv,
	.unlinkat_fn = streams_xattr_unlinkat,
	.renameat_fn = streams_xattr_renameat,
	.ftruncate_fn = streams_xattr_ftruncate,
	.fallocate_fn = streams_xattr_fallocate,
	.fstreaminfo_fn = streams_xattr_fstreaminfo,

	.fsync_send_fn = streams_xattr_fsync_send,
	.fsync_recv_fn = streams_xattr_fsync_recv,

	.lock_fn = streams_xattr_lock,
	.getlock_fn = streams_xattr_getlock,
	.filesystem_sharemode_fn = streams_xattr_filesystem_sharemode,
	.linux_setlease_fn = streams_xattr_linux_setlease,
	.strict_lock_check_fn = streams_xattr_strict_lock_check,
	.fcntl_fn = streams_xattr_fcntl,

	.fchown_fn = streams_xattr_fchown,
	.fchmod_fn = streams_xattr_fchmod,

	.fgetxattr_fn = streams_xattr_fgetxattr,
	.flistxattr_fn = streams_xattr_flistxattr,
	.fremovexattr_fn = streams_xattr_fremovexattr,
	.fsetxattr_fn = streams_xattr_fsetxattr,
};

static_decl_vfs;
NTSTATUS vfs_streams_xattr_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "streams_xattr",
				&vfs_streams_xattr_fns);
}
