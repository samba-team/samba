/*
 * Unix SMB/CIFS implementation.
 * Utility functions for reparse points.
 *
 * Copyright (C) Jeremy Allison 2018
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "util_reparse.h"
#include "libcli/smb/reparse.h"
#include "source3/smbd/proto.h"

static NTSTATUS fsctl_get_reparse_point_reg(struct files_struct *fsp,
					    TALLOC_CTX *ctx,
					    uint8_t **_out_data,
					    uint32_t max_out_len,
					    uint32_t *_out_len)
{
	uint8_t *val = NULL;
	ssize_t sizeret;
	NTSTATUS status;

	/*
	 * 64k+8 bytes is the maximum reparse point length
	 * possible
	 */

	val = talloc_array(ctx, uint8_t, MIN(max_out_len, 65536 + 8));
	if (val == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sizeret = SMB_VFS_FGETXATTR(fsp,
				    SAMBA_XATTR_REPARSE_ATTRIB,
				    val,
				    talloc_get_size(val));

	if ((sizeret == -1) && (errno == ERANGE)) {
		status = NT_STATUS_BUFFER_TOO_SMALL;
		goto fail;
	}

	if ((sizeret == -1) && (errno == ENOATTR)) {
		DBG_DEBUG(SAMBA_XATTR_REPARSE_ATTRIB " does not exist\n");
		status = NT_STATUS_NOT_A_REPARSE_POINT;
		goto fail;
	}

	if (sizeret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("SMB_VFS_FGETXATTR failed: %s\n", strerror(errno));
		goto fail;
	}

	*_out_data = val;
	*_out_len = sizeret;
	return NT_STATUS_OK;
fail:
	TALLOC_FREE(val);
	return status;
}

static NTSTATUS fsctl_get_reparse_point_int(
	struct files_struct *fsp,
	const struct reparse_data_buffer *reparse_data,
	TALLOC_CTX *ctx,
	uint8_t **_out_data,
	uint32_t max_out_len,
	uint32_t *_out_len)
{
	uint8_t *out_data = NULL;
	ssize_t out_len;

	out_len = reparse_data_buffer_marshall(reparse_data, NULL, 0);
	if (out_len == -1) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}
	if (max_out_len < out_len) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	out_data = talloc_array(ctx, uint8_t, out_len);
	if (out_data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	reparse_data_buffer_marshall(reparse_data, out_data, out_len);

	*_out_data = out_data;
	*_out_len = out_len;

	return NT_STATUS_OK;
}

static NTSTATUS fsctl_get_reparse_point_fifo(struct files_struct *fsp,
					     TALLOC_CTX *ctx,
					     uint8_t **_out_data,
					     uint32_t max_out_len,
					     uint32_t *_out_len)
{
	struct reparse_data_buffer reparse_data = {
		.tag = IO_REPARSE_TAG_NFS,
		.parsed.nfs.type = NFS_SPECFILE_FIFO,
	};

	return fsctl_get_reparse_point_int(
		fsp, &reparse_data, ctx, _out_data, max_out_len, _out_len);
}

static NTSTATUS fsctl_get_reparse_point_sock(struct files_struct *fsp,
					     TALLOC_CTX *ctx,
					     uint8_t **_out_data,
					     uint32_t max_out_len,
					     uint32_t *_out_len)
{
	struct reparse_data_buffer reparse_data = {
		.tag = IO_REPARSE_TAG_NFS,
		.parsed.nfs.type = NFS_SPECFILE_SOCK,
	};

	return fsctl_get_reparse_point_int(
		fsp, &reparse_data, ctx, _out_data, max_out_len, _out_len);
}

static NTSTATUS fsctl_get_reparse_point_dev(struct files_struct *fsp,
					    uint64_t nfs_type,
					    dev_t rdev,
					    TALLOC_CTX *ctx,
					    uint8_t **_out_data,
					    uint32_t max_out_len,
					    uint32_t *_out_len)
{
	struct reparse_data_buffer reparse_data = {
		.tag = IO_REPARSE_TAG_NFS,
		.parsed.nfs.type = nfs_type,
		.parsed.nfs.data.dev.major = unix_dev_major(rdev),
		.parsed.nfs.data.dev.minor = unix_dev_minor(rdev),
	};

	return fsctl_get_reparse_point_int(
		fsp, &reparse_data, ctx, _out_data, max_out_len, _out_len);
}

static NTSTATUS fsctl_get_reparse_point_lnk(struct files_struct *fsp,
					    TALLOC_CTX *mem_ctx,
					    uint8_t **_out_data,
					    uint32_t max_out_len,
					    uint32_t *_out_len)
{
	struct reparse_data_buffer *reparse = NULL;
	struct smb_filename *parent_fname = NULL;
	struct smb_filename *base_name = NULL;
	NTSTATUS status;

	status = parent_pathref(talloc_tos(),
				fsp->conn->cwd_fsp,
				fsp->fsp_name,
				&parent_fname,
				&base_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("parent_pathref(%s) failed: %s\n",
			  fsp_str_dbg(fsp),
			  nt_errstr(status));
		return status;
	}

	status = read_symlink_reparse(talloc_tos(),
				      parent_fname->fsp,
				      base_name,
				      &reparse);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("read_symlink_reparse failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	status = fsctl_get_reparse_point_int(
		fsp, reparse, mem_ctx, _out_data, max_out_len, _out_len);
	TALLOC_FREE(reparse);
	return status;
}

NTSTATUS fsctl_get_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 uint32_t *_reparse_tag,
				 uint8_t **_out_data,
				 uint32_t max_out_len,
				 uint32_t *_out_len)
{
	uint32_t dos_mode;
	uint8_t *out_data = NULL;
	uint32_t out_len = 0;
	uint32_t reparse_tag = 0;
	const uint8_t *reparse_data = NULL;
	size_t reparse_data_length;
	NTSTATUS status = NT_STATUS_NOT_A_REPARSE_POINT;

	dos_mode = fdos_mode(fsp);
	if ((dos_mode & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
		return NT_STATUS_NOT_A_REPARSE_POINT;
	}

	switch (fsp->fsp_name->st.st_ex_mode & S_IFMT) {
	case S_IFREG:
		DBG_DEBUG("%s is a regular file\n", fsp_str_dbg(fsp));
		status = fsctl_get_reparse_point_reg(
			fsp, mem_ctx, &out_data, max_out_len, &out_len);
		break;
	case S_IFIFO:
		DBG_DEBUG("%s is a fifo\n", fsp_str_dbg(fsp));
		status = fsctl_get_reparse_point_fifo(
			fsp, mem_ctx, &out_data, max_out_len, &out_len);
		break;
	case S_IFSOCK:
		DBG_DEBUG("%s is a socket\n", fsp_str_dbg(fsp));
		status = fsctl_get_reparse_point_sock(
			fsp, mem_ctx, &out_data, max_out_len, &out_len);
		break;
	case S_IFBLK:
		DBG_DEBUG("%s is a block device\n", fsp_str_dbg(fsp));
		status = fsctl_get_reparse_point_dev(
			fsp,
			NFS_SPECFILE_BLK,
			fsp->fsp_name->st.st_ex_rdev,
			mem_ctx,
			&out_data,
			max_out_len,
			&out_len);
		break;
	case S_IFCHR:
		DBG_DEBUG("%s is a character device\n", fsp_str_dbg(fsp));
		status = fsctl_get_reparse_point_dev(
			fsp,
			NFS_SPECFILE_CHR,
			fsp->fsp_name->st.st_ex_rdev,
			mem_ctx,
			&out_data,
			max_out_len,
			&out_len);
		break;
	case S_IFLNK:
		DBG_DEBUG("%s is a symlink\n", fsp_str_dbg(fsp));
		status = fsctl_get_reparse_point_lnk(
			fsp, mem_ctx, &out_data, max_out_len, &out_len);
		break;
	default:
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("failed: %s\n", nt_errstr(status));
		return status;
	}

	status = reparse_buffer_check(out_data,
				      out_len,
				      &reparse_tag,
				      &reparse_data,
				      &reparse_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Invalid reparse data: %s\n", nt_errstr(status));
		TALLOC_FREE(out_data);
		return status;
	}

	*_reparse_tag = reparse_tag;
	*_out_data = out_data;
	*_out_len = out_len;

	return NT_STATUS_OK;
}

NTSTATUS fsctl_get_reparse_tag(struct files_struct *fsp,
			       uint32_t *_reparse_tag)
{
	uint8_t *out_data = NULL;
	uint32_t out_len;
	NTSTATUS status;

	status = fsctl_get_reparse_point(fsp,
					 talloc_tos(),
					 _reparse_tag,
					 &out_data,
					 UINT32_MAX,
					 &out_len);
	TALLOC_FREE(out_data);
	return status;
}

NTSTATUS fsctl_set_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 const uint8_t *in_data,
				 uint32_t in_len)
{
	uint32_t reparse_tag;
	const uint8_t *reparse_data = NULL;
	size_t reparse_data_length;
	uint32_t existing_tag;
	NTSTATUS status;
	uint32_t dos_mode;
	int ret;

	DBG_DEBUG("Called on %s\n", fsp_str_dbg(fsp));

	if (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) {
		DBG_DEBUG("Can only set reparse point for regular files\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	status = reparse_buffer_check(in_data,
				      in_len,
				      &reparse_tag,
				      &reparse_data,
				      &reparse_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("check_reparse_data_buffer failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	DBG_DEBUG("reparse tag=%" PRIX32 ", length=%zu\n",
		  reparse_tag,
		  reparse_data_length);

	status = fsctl_get_reparse_tag(fsp, &existing_tag);
	if (NT_STATUS_IS_OK(status) && (existing_tag != reparse_tag)) {
		DBG_DEBUG("Can't overwrite tag %" PRIX32 " with tag %" PRIX32
			  "\n",
			  existing_tag,
			  reparse_tag);
		return NT_STATUS_IO_REPARSE_TAG_MISMATCH;
	}

	/* Store the data */
	ret = SMB_VFS_FSETXATTR(
		fsp, SAMBA_XATTR_REPARSE_ATTRIB, in_data, in_len, 0);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("setxattr fail on %s - %s\n",
			  fsp_str_dbg(fsp),
			  strerror(errno));
		return status;
	}

	/*
	 * Files with reparse points don't have the ATTR_NORMAL bit
	 * set
	 */
	dos_mode = fdos_mode(fsp);
	dos_mode &= ~FILE_ATTRIBUTE_NORMAL;
	dos_mode |= FILE_ATTRIBUTE_REPARSE_POINT;

	status = SMB_VFS_FSET_DOS_ATTRIBUTES(fsp->conn, fsp, dos_mode);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("set reparse attr fail on %s - %s\n",
			fsp_str_dbg(fsp),
			nt_errstr(status));
		return status;
	}

	fsp->fsp_name->st.cached_dos_attributes = dos_mode;

	return NT_STATUS_OK;
}

NTSTATUS fsctl_del_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 const uint8_t *in_data,
				 uint32_t in_len)
{
	uint32_t existing_tag;
	uint32_t reparse_tag;
	const uint8_t *reparse_data = NULL;
	size_t reparse_data_length;
	NTSTATUS status;
	uint32_t dos_mode;
	int ret;

	status = fsctl_get_reparse_tag(fsp, &existing_tag);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = reparse_buffer_check(in_data,
				      in_len,
				      &reparse_tag,
				      &reparse_data,
				      &reparse_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (reparse_data_length != 0) {
		return NT_STATUS_IO_REPARSE_DATA_INVALID;
	}

	if (existing_tag != reparse_tag) {
		DBG_DEBUG("Expect correct tag %" PRIX32 ", got tag %" PRIX32
			  "\n",
			  existing_tag,
			  reparse_tag);
		return NT_STATUS_IO_REPARSE_TAG_MISMATCH;
	}

	ret = SMB_VFS_FREMOVEXATTR(fsp, SAMBA_XATTR_REPARSE_ATTRIB);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		DBG_DEBUG("removexattr fail on %s - %s\n",
			  fsp_str_dbg(fsp),
			  strerror(errno));
		return status;
	}

	/*
	 * Files with reparse points don't have the ATTR_NORMAL bit
	 * set
	 */
	dos_mode = fdos_mode(fsp);
	dos_mode &= ~FILE_ATTRIBUTE_REPARSE_POINT;

	status = SMB_VFS_FSET_DOS_ATTRIBUTES(fsp->conn, fsp, dos_mode);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("set reparse attr fail on %s - %s\n",
			fsp_str_dbg(fsp),
			nt_errstr(status));
		return status;
	}

	fsp->fsp_name->st.cached_dos_attributes = dos_mode;

	return NT_STATUS_OK;
}
